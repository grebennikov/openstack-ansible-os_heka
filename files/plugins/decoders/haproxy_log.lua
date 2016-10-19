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
local timestamp = "[" * l.Cg(dt.build_strftime_grammar("%d/%b/%Y:%H:%M:%S") * dt.time_secfrac / dt.time_to_ns, "Timestamp") * "]"
local log_date = l.Cg(dt.rfc3164_timestamp, "LogDate")
local host = (l.alnum^1 + l.S("-_<>."))^1
--remove if necessary
--local unknown = "<" * (l.alnum^1)^1 * ">"
--
local proc = l.P"haproxy[" * l.Cg(l.R("09")^1, "pid") * l.P"]:" * l.Cg(l.Cc"haproxy", "Type")
local remote_addr = l.Cg(ip.v4, "remote_addr") * ":" * l.Cg(l.R("09")^1, "port")

local request = l.P{'"' * l.Cg(((1 - l.P'"') + l.V(1))^0, "request") * '"'}
local status = l.Cg(l.digit * l.digit * l.digit, "status")
local bytes = l.Cg(l.digit^1, "bytes")
local srv_data = host * sp * host * l.P"/" * host
local tm = l.Cg((l.digit^1 + l.P"/" + l.P"-")^1, "tm")
local conn = l.Cg((l.digit^1 + l.P"/")^1, "conn")
local queue = l.Cg((l.digit^1 + l.P"/")^1, "queue")
local hap_generic_token = (1 - l.space)^1
local CC = l.Cg(hap_generic_token, "captured_request_cookie")
local CS = l.Cg(hap_generic_token, "captured_response_cookie")
local hap_term_state_default = l.P"-"
local hap_term_state_one = l.Cg(l.S"-CSPIRDLUKcs", 'sess_term1_cause')
local hap_term_state_two = l.Cg(l.S"-DTHCRLQ", 'sess_term2_state')
local hap_term_state_three = l.Cg(l.S"-NIDVEOU", 'sess_term3_cookie_client')
local hap_term_state_four = l.Cg(l.S"-PDRNUI", 'sess_term4_cookie_serv_op')
local tsc_http = hap_term_state_one
                 * hap_term_state_two
                 * hap_term_state_three
                 * hap_term_state_four
local tsc_tcp = hap_term_state_one
                * hap_term_state_two

local any = l.Cg((l.alnum^1)^1, any)


local msg_grammar_http = l.Ct(log_date * sp * host * sp * proc * sp * remote_addr * sp * timestamp * sp  * srv_data * sp * tm * sp * status * sp * bytes * sp * CC * sp * CS * sp * tsc_http * sp * conn * sp * queue * sp * request)
--local msg_grammar_http = l.Ct(unknown * log_date * sp * host * sp * proc * sp * remote_addr * sp * timestamp * sp  * srv_data * sp * tm * sp * status * sp * bytes * sp * CC * sp * CS * sp * tsc_http * sp * conn * sp * queue * sp * request)

local msg_grammar_tcp = l.Ct(log_date * sp * host * sp * proc * sp * remote_addr * sp * timestamp * sp  * srv_data * sp * tm * sp * bytes * sp * tsc_tcp * sp * conn * sp * queue)
--local msg_grammar_tcp = l.Ct(unknown * log_date * sp * host * sp * proc * sp * remote_addr * sp * timestamp * sp  * srv_data * sp * tm * sp * bytes * sp * tsc_tcp * sp * conn * sp * queue)

local msg_grammar_simple = l.Ct(log_date * sp * host * sp * proc * sp * any)
--local msg_grammar_simple = l.Ct(unknown * log_date * sp * host * sp * proc * sp * any)

function process_message ()
    local log = read_message("Payload")

    local m_http = msg_grammar_http:match(log)
    local m_tcp = msg_grammar_tcp:match(log)
    local m_simple = msg_grammar_simple:match(log)

    if m_http then
        msg.Fields = {}
        msg.Payload = log
        msg.Timestamp = m_http.Timestamp
        msg.Severity = utils.label_to_severity_map['INFO']
        msg.Logger = 'haproxy'
        msg.Hostname = m_http.hostname
        msg.Pid = m_http.pid
        msg.Fields.remote_addr = m_http.remote_addr
        msg.Fields.request = m_http.request
        msg.Fields.bytes = m_http.bytes
        msg.Fields.severity_label = utils.severity_to_label_map[msg.Severity]
        msg.Fields.programname = 'haproxy'
        msg.Fields.sess_term_cause = m_http.sess_term1_cause
        msg.Fields.sess_term_state = m_http.sess_term2_state
        msg.Fields.timings = m_http.tm
        msg.Fields.connection_details = m_http.conn
    elseif m_tcp then
        msg.Fields = {}
        msg.Payload = log
        msg.Timestamp = m_tcp.Timestamp
        msg.Severity = 7
        msg.Logger = 'haproxy'
        msg.Hostname = m_tcp.hostname
        msg.Timestamp = m_tcp.timestamp
        msg.Pid = m_tcp.pid
        msg.Fields.remote_addr = m_tcp.remote_addr
        msg.Fields.request = m_tcp.request
        msg.Fields.status = m_tcp.status
        msg.Fields.bytes = m_tcp.bytes
        msg.Fields.severity_label = 'INFO'
        msg.Fields.programname = 'haproxy'
        msg.Fields.sess_term_cause = m_tcp.sess_term1_cause
        msg.Fields.sess_term_state = m_tcp.sess_term2_state
        msg.Fields.timings = m_tcp.tm
        msg.Fields.connection_details = m_tcp.conn
    else
       if not m_simple then return -1 end
       msg.Fields = {}
       msg.Payload = log
       msg.Timestamp = m_simple.Timestamp
       msg.Logger = 'haproxy'
       msg.Hostname = m_simple.hostname
       msg.Pid = m_simple.pid
       msg.Severity = utils.label_to_severity_map['ERROR']
       msg.Fields.severity_label = utils.severity_to_label_map[msg.Severity]
       msg.Fields.programname = 'haproxy'
       
    end
 

	utils.inject_tags(msg)
    return utils.safe_inject_message(msg)
end
