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

local syslog_grammar = syslog.build_rsyslog_grammar("%TIMESTAMP% %HOSTNAME% %syslogtag%%msg:::sp-if-no-1st-sp%%msg:::drop-last-lf%\n")
local sp = l.space

local timestamp = l.Cg(dt.build_strftime_grammar("%a %b %d %H:%M:%S") * dt.time_secfrac, "Timestamp")

local context = "[" * l.Cg((l.alnum^1)^1, "context") * "]"

local message = l.Cg(l.P  (1)^1, "message")

local msg_grammar = l.Ct(timestamp * sp * context * sp * message)






function process_message ()
    local log = read_message("Payload")

    local m = msg_grammar:match(log)
    if not m then return -1 end
       msg.Fields = {}
       msg.Payload = log
       msg.Timestamp = m.Timestamp
       msg.Severity = utils.label_to_severity_map['INFO']
       msg.Fields.severity_label = utils.severity_to_label_map[msg.Severity]
       msg.Fields.context = m.context
       msg.Fields.message = m.message
       msg.Fields.programname = 'mongodb'

       utils.inject_tags(msg)
    return utils.safe_inject_message(msg)
end

