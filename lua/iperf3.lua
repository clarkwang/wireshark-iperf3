--
-- Author: Clark Wang <dearvoid @ gmail.com>
--

local BOOL_0 = false
local BOOL_1 = true

local g = {
    PORT = 5201,

    udp = {
      --packets = 0,
      --visited = 0,
      --streams = {},
    },

    tcp = {
      --packets = 0,
      --visited = 0,
    },

    debug = {
        on = BOOL_0,
    },

    states = {
        TEST_START       = 1,
        TEST_RUNNING     = 2,
        RESULT_REQUEST   = 3,  -- not used
        TEST_END         = 4,
        STREAM_BEGIN     = 5,  -- not used
        STREAM_RUNNING   = 6,  -- not used
        STREAM_END       = 7,  -- not used
        ALL_STREAMS_END  = 8,  -- not used
        PARAM_EXCHANGE   = 9,
        CREATE_STREAMS   = 10,
        SERVER_TERMINATE = 11,
        CLIENT_TERMINATE = 12,
        EXCHANGE_RESULTS = 13,
        DISPLAY_RESULTS  = 14,
        IPERF_START      = 15,
        IPERF_DONE       = 16,

        --
        -- Don't write `-2 & 0xff' which is not supported in Lua 5.2.
        --
        SERVER_ERROR     = 254, -- -2
        ACCESS_DENIED    = 255, -- -1
    },
    states_id2name = {},
}

for name, id in pairs(g.states) do
    g.states_id2name[id] = name
end

g.fields = {
    state = ProtoField.uint8("iperf3.state", "State", base.DEC, g.states_id2name),

    data_len = ProtoField.uint32("iperf3.datalen", "Data Len", base.DEC),
    data     = ProtoField.bytes ("iperf3.data",    "Data"),
    unknown  = ProtoField.bytes ("iperf3.unknown", "Data (?)"),

    cookie = ProtoField.string("iperf3.cookie", "Cookie"),
    json   = ProtoField.string("iperf3.json",   "JSON"),
}
g.ufields = {
    magic = ProtoField.uint32("iperf3u.magic", "Magic"),

    -- The timestamp may be "wrong" because it may be got with
    -- clock_gettime(CLOCK_MONOTONIC).
    time_str  = ProtoField.string("iperf3u.time_str",  "Time"),
    time_sec  = ProtoField.uint32("iperf3u.time_sec",  "sec",  base.DEC),
    time_usec = ProtoField.uint32("iperf3u.time_usec", "usec", base.DEC),

    seq32 = ProtoField.uint32("iperf3u.seq32", "Seq (32bit)", base.DEC),
    seq64 = ProtoField.uint64("iperf3u.seq64", "Seq (64bit)", base.DEC),

    data    = ProtoField.bytes("iperf3u.data",    "Data"),
    unknown = ProtoField.bytes("iperf3u.unknown", "Data (?)"),
}

----------------------------------------------------------------------

local function debug(...)
    if g.debug.on then
        print('.. ' .. string.format(...) )
    end
end

local function min(a, b)
    return a < b and a or b
end

----------------------------------------------------------------------

local Fields = {}
do
    local fields = {
        'ip.src_host', 'ip.dst_host',
        'tcp.seq', 'tcp.seq_raw',
        'tcp.ack', 'tcp.ack_raw',
        'udp.stream',
    }

    for _, f in ipairs(fields) do
        Fields[f] = Field.new(f)
    end
end

local function pfield(field)
    return Fields[field]()
end

----------------------------------------------------------------------

local function iter_states(tvbuf, subtree, offset, count)
    local bytes = tvbuf:bytes(offset, count)

    for i = 0, count - 1 do
        local state = bytes:get_index(i)
        if not g.states_id2name[state] then
            subtree:add(g.fields.unknown, tvbuf(offset, count) )
            return
        end
    end

    for i = 0, count - 1 do
        subtree:add(g.fields.state, tvbuf(offset + i, 1) )
    end
end

local function add_json(subtree, range)
    local N_LINE = 80
    local length = range:len()

    local desc = string.format('JSON (len=%d)', length)
    local childtree = subtree:add(g.fields.json, range, '..', desc)

    local offset = 0
    while offset < length do
        local count = min(N_LINE, length - offset)
        childtree:add(g.fields.json, range:range(offset, count) )
        offset = offset + N_LINE
    end
end

local function c2s(tvbuf, pinfo, subtree)
    local length = tvbuf:len()
    local range = tvbuf()

    -- state
    if length == 1 then
        iter_states(tvbuf, subtree, 0, length)
        return
    end

    -- data/JSON length
    if length == 4 then
        subtree:add(g.fields.data_len, range)
        return
    end

    -- unknown
    if length < 4 then
        subtree:add(g.fields.unknown, range)
        return
    end

    -- JSON
    local first2 = range:raw(0, 2)
    if first2 == '{"' then
        local last1c = range:raw(length - 1)
        if last1c == '}' then
            add_json(subtree, range)
        else
            -- not JSON?
            subtree:add(g.fields.unknown, range)
        end
        return
    end

    -- The test cookie (37 bytes) right after 3-way handshake
    if length == 37 and pfield('tcp.seq').value == 1 then
        if range:raw(length - 1) == '\000' then
            subtree:add(g.fields.cookie, range)
        else
            subtree:add(g.fields.unknown, range)
        end

        return
    end

    -- [data] Test data
    if length > 37 then
        local desc = string.format('Data (%d bytes)', length)
        subtree:add(g.fields.data, range, range:raw(), desc)
        return
    else
        subtree:add(g.fields.unknown, range)
        return
    end
end

local function s2c(tvbuf, pinfo, subtree)
    local length = tvbuf:len()
    local range = tvbuf()

    if length < 4 then
        iter_states(tvbuf, subtree, 0, length)
        return
    end

    -- [data] length
    if length == 4 then
        subtree:add(g.fields.data_len, range)
        return
    end

    if length > 4 then
        local first2 = range:raw(0, 2)
        if first2 == '{"' then
            local raw = range:raw()
            local offset = string.match(raw, '^%b{}()')
            if offset then
                -- make it 0-indexed
                offset = offset - 1
                add_json(subtree, tvbuf(0, offset) )
                if offset == length then
                    -- no more data after the JSON text
                    return
                elseif length - offset >= 4 then
                    -- not states
                    subtree:add(g.fields.unknown, tvbuf(offset) )
                    return
                else
                    iter_states(tvbuf, subtree, offset, length - offset)
                    return
                end
            else
                -- not JSON?
                subtree:add(g.fields.unknown, range)
                return
            end
        else
            -- not JSON
            subtree:add(g.fields.unknown, range)
            return
        end

        return
    end
end

----------------------------------------------------------------------

local tcproto = Proto("iperf3", "iperf3-tcp")
tcproto.fields = g.fields

function tcproto.dissector(tvbuf, pinfo, tree)
    pinfo.cols.protocol = tcproto.name

  --debug('%s', pfield('ip.src_host') )

    g.tcp.packets = g.tcp.packets + 1
    if not pinfo.visited then
        g.tcp.visited = g.tcp.visited + 1
      --debug('#tcp = %d', g.tcp.visited)
    end

    local desc = string.format("iperf3tcp - github.com/clarkwang")
    local subtree = tree:add(tcproto, tvbuf(), desc)

    if pinfo.dst_port == g.PORT then
        return c2s(tvbuf, pinfo, subtree)
    else
        return s2c(tvbuf, pinfo, subtree)
    end
end

function tcproto.init()
    g.tcp = {
        packets = 0,
        visited = 0,
    }
end

----------------------------------------------------------------------

local udproto = Proto("iperf3u", "iperf3-udp")
udproto.fields = g.ufields

local function udp_seqlen(tvbuf, pinfo)
    local num = pfield('udp.stream').value
    if not g.udp.streams[num] then
        g.udp.streams[num] = { seqs = {}, seqlen = nil, }
    end

    local stream = g.udp.streams[num]
    if stream.seqlen then
        return stream.seqlen
    end

    if pinfo.visited then
        return -1
    end

    if #stream.seqs < 3 then
        local seq32 = tvbuf(8, 4):uint()
        table.insert(stream.seqs, seq32)
    end

    if #stream.seqs == 2 then
        -- packets #1 and #2 have the same seq32 num
        if stream.seqs[1] == stream.seqs[2] then
            stream.seqlen = 8
            return stream.seqlen
        end
    elseif #stream.seqs == 3 then
        -- packets #2 and #3 have the same seq32 num
        if stream.seqs[2] == stream.seqs[3] then
            stream.seqlen = 8
        else
            -- packets #1, #2 and #3 all have different seq32 num
            stream.seqlen = 4
        end
        return stream.seqlen
    end

    -- the seq len cannot be determined yet.
    return -1
end

function udproto.dissector(tvbuf, pinfo, tree)
    pinfo.cols.protocol = udproto.name

    g.udp.packets = g.udp.packets + 1
  --debug('#udp = %d', g.udp.packets)

    local desc = string.format("iperf3udp - github.com/clarkwang")
    local subtree = tree:add(udproto, tvbuf(), desc)

    local range = tvbuf()
    local length = tvbuf:len()

    if length == 4 then
        local magic = range:uint()
        -- 123456789 (0x075BCD15)
        -- 987654321 (0x3ADE68B1)
        if magic == 123456789 or magic == 987654321 then
            subtree:add(g.ufields.magic, range)
        else
            subtree:add_le(g.ufields.magic, range)
        end
        return
    end

    if length <= 16 then
        subtree:add(g.ufields.unknown, range)
        return
    end

    -- The timestamp may be "wrong" because it may be got with
    -- clock_gettime(CLOCK_MONOTONIC).
    do
        local sec  = tvbuf(0, 4):uint()
        local usec = tvbuf(4, 4):uint()
        local time = sec + usec / 1e6
        if BOOL_0 then
            time = format_date(time)
        else
            time = string.format('%.2f', time)
        end
        local timetree = subtree:add(g.ufields.time_str, tvbuf(0, 8), time)
        timetree:add(g.ufields.time_sec,  tvbuf(0, 4) )
        timetree:add(g.ufields.time_usec, tvbuf(4, 4) )
    end

    local seqlen = udp_seqlen(tvbuf, pinfo)
    if seqlen == 4 then
        -- 32bit counter
        subtree:add(g.ufields.seq32, tvbuf(8, 4) )
    elseif seqlen == 8 then
        -- 64bit counter
        subtree:add(g.ufields.seq64, tvbuf(8, 8) )
    else
        return
    end

    local hdrlen = 8 + seqlen
    local desc = string.format('Data (%d bytes)', length - hdrlen)
    local databuf = tvbuf(hdrlen)
    subtree:add(g.ufields.data, databuf, databuf:raw(), desc)
end

function udproto.init()
    g.udp = {
        packets = 0,
        visited = 0,
        streams = {},
    }
end

----------------------------------------------------------------------

DissectorTable.get("tcp.port"):add(g.PORT, tcproto)
DissectorTable.get("udp.port"):add(g.PORT, udproto)
