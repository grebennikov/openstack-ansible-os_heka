local dt = require "date_time"
local ip = require "ip_address"
local l = require 'lpeg'
local syslog = require "syslog"

local patt = require 'patterns'
local utils  = require 'lma_utils'
local table_utils = require 'table_utils'


l.locale(l)

local msg = {
Timestamp   = nil,
Type        = 'log',
Hostname    = nil,
Payload     = nil,
Pid         = nil,
Fields      = nil,
Severity    = nil,

}

local severity_to_label_map_ceph = {
    ['-1']  = 3,
    ['0']   = 6,
    ['1']   = 6,
    ['5']   = 7,
    ['10']  = 7,
    ['15']  = 7,
    ['20']  = 7,
    ['25']  = 7,
    ['30']  = 7,
}

local sp = l.space
local timestamp = l.Cg(patt.TimestampTable, "Timestamp")
local hash = l.Cg((l.alnum^1)^1, "hash")
local sev = l.Cg(l.P" "^0 * l.Cg((l.alnum^1 + l.P"-")^0), "sev")
local any = l.Cg(l.P  (1)^1, "any")

local msg_grammar = l.Ct(timestamp * sp * hash * sp * sev * sp * any)


function process_message ()

    local log = read_message("Payload")

    local m = msg_grammar:match(log)

       if not m then return -1 end
       msg.Fields = {}
       msg.Payload = log
       msg.Timestamp = m.Timestamp
       msg.Fields.sev = m.sev
       msg.Severity = severity_to_label_map_ceph[m.sev]
       msg.Fields.severity_label = utils.severity_to_label_map[msg.Severity]

       utils.inject_tags(msg)
    return utils.safe_inject_message(msg)
end
