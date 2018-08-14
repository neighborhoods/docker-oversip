# coding: utf-8

#
# OverSIP - Server Logic.
#




### Custom Application Code:


# Define here your custom code for the application running on top of OverSIP.
# Here you can load thirdy-party libraries and so on.
#
# require "some-gem"
#
module MyExampleApp
  extend ::OverSIP::Logger

  class << self
    attr_reader :do_outbound_mangling, :do_user_assertion
  end

  # Set this to _true_ if the SIP registrar behind OverSIP does not support Path.
  # OverSIP::Modules::OutboundMangling methods will be used.
  @do_outbound_mangling = true

  # Set this to _true_ if the SIP proxy/server behind OverSIP performing the authentication
  # is ready to accept a P-Asserted-Identity header from OverSIP indicating the already
  # asserted SIP user of the client's connection (this avoids authenticating all the requests
  # but the first one).
  # OverSIP::Modules::UserAssertion methods will be used.
  @do_user_assertion = true
end

module OverSIP::SIP
  class NameAddr
    def modified!
      @name_addr_modified = true
      @uri_modified = true
    end
    def modified?
      # Oversip uses this to determine if header should be rebuilt, but the
      # to_s method resets this flag (it has a side effect) which is a buggy
      # premature optimization that breaks things (printing the Uri for debugging
      # resets the flag; it's an anti-heisenbug)
      true
    end
  end
  class Uri
    def modified!
      @uri_modified = true
    end
    def modified?
      true
    end
  end
end

# Fixup URIs to ensure they are formatted correctly
def fixup_uri uri
  return uri unless /^\d+$/.match uri.user

  number = uri.user

  if match = /^1?([2-9]\d{9})$/.match(number)
    # Handle international numbers (with U.S. internation dialing prefix 011)
    number = "+1#{match.captures[0]}"
  elsif match = /^011(\d+)$/.match(number)
    # Handle local/long-distance numbers that might not have a "1" prefix
    number = "+#{match.captures[0]}"
  end

  # All other numbers passed as-is (e.g. 911; no plus sign added)

  uri.user = number

  return uri
end


### OverSIP SIP Events:


# This method is called when a SIP request is received.
#
def (OverSIP::SipEvents).on_request request

  log_info "#{request.sip_method} from #{request.from.uri} (UA: #{request.header("User-Agent")}) to #{request.ruri} via #{request.transport.upcase} #{request.source_ip} : #{request.source_port}"

  # Check Max-Forwards value (max 10).
  return unless request.check_max_forwards 10

  # Assume all the traffic is from clients and help them with NAT issues
  # by forcing rport usage and Outbound mechanism.
  request.fix_nat

  # In-dialog requests.
  if request.in_dialog?
    if request.loose_route
      log_debug "proxying in-dialog #{request.sip_method}"
      proxy = ::OverSIP::SIP::Proxy.new :proxy_in_dialog
      proxy.route request
    else
      unless request.sip_method == :ACK
        log_notice "forbidden in-dialog request without top Route pointing to us => 403"
        request.reply 403, "forbidden in-dialog request without top Route pointing to us"
      else
        log_notice "ignoring not loose routing ACK"
      end
    end
    return
  end

  # Initial requests.

  # Check that the request does not contain a top Route pointing to another server.
  if request.loose_route
    unless request.sip_method == :ACK
      log_notice "pre-loaded Route not allowed here => 403"
      request.reply 403, "Pre-loaded Route not allowed"
    else
      log_notice "ignoring ACK initial request"
    end
    return
  end

  if MyExampleApp.do_outbound_mangling
    # Extract the Outbound flow token from the RURI.
    ::OverSIP::Modules::OutboundMangling.extract_outbound_from_ruri request
  end

  # The request goes to a client using Outbound through OverSIP.
  if request.incoming_outbound_requested?
    log_info "routing initial request to an Outbound client"

    proxy = ::OverSIP::SIP::Proxy.new :proxy_to_users

    proxy.on_success_response do |response|
      log_info "incoming Outbound on_success_response: #{response.status_code} '#{response.reason_phrase}'"
    end

    proxy.on_failure_response do |response|
      log_info "incoming Outbound on_failure_response: #{response.status_code} '#{response.reason_phrase}'"
    end

    # on_error() occurs when no SIP response was received fom the peer and, instead, we
    # got some other internal error (timeout, connection error, DNS error....).
    proxy.on_error do |status, reason|
      log_notice "incoming Outbound on_error: #{status} '#{reason}'"
    end

    # Route the request and return.
    proxy.route request
    return
  end

  # An initial request with us (OverSIP) as final destination, ok, received, bye...
  if request.destination_myself?
    log_info "request for myself => 404"
    request.reply 404, "Ok, I'm here"
    return
  end

  if request.sip_method == :INVITE
    log_debug "got ruri #{request.ruri}"
    log_debug "got from #{request.from}"
    log_debug "got to #{request.to}"

    fixup_uri request.ruri
    fixup_uri request.to
    fixup_uri request.from

    log_debug "modified ruri #{request.ruri}"
    log_debug "modified from #{request.from}"
    log_debug "modified to #{request.to}"
  end

  # An outgoing initial request.
  case request.sip_method

  when :INVITE, :MESSAGE, :OPTIONS, :SUBSCRIBE, :PUBLISH, :REFER

    if MyExampleApp.do_user_assertion
      ::OverSIP::Modules::UserAssertion.add_pai request
    end

    proxy = ::OverSIP::SIP::Proxy.new :proxy_out

    proxy.on_provisional_response do |response|
      log_info "on_provisional_response: #{response.status_code} '#{response.reason_phrase}'"
    end

    proxy.on_success_response do |response|
      log_info "on_success_response: #{response.status_code} '#{response.reason_phrase}'"
    end

    proxy.on_failure_response do |response|
      log_info "on_failure_response: #{response.status_code} '#{response.reason_phrase}'"
    end

    proxy.on_error do |status, reason|
      log_notice "on_error: #{status} '#{reason}'"
    end

    proxy.on_invite_timeout do
      log_notice "INVITE timeout, no final response before Timer C expires."
    end

    proxy.route request
    return

  when :REGISTER

    proxy = ::OverSIP::SIP::Proxy.new :proxy_out

    if MyExampleApp.do_outbound_mangling
      # Contact mangling for the case in which the registrar does not support Path.
      ::OverSIP::Modules::OutboundMangling.add_outbound_to_contact proxy
    end

    proxy.on_success_response do |response|
      if MyExampleApp.do_user_assertion
        # The registrar replies 200 after a REGISTER with credentials so let's assert
        # the current SIP user to this connection.
        ::OverSIP::Modules::UserAssertion.assert_connection response
      end
    end

    proxy.on_failure_response do |response|
      if MyExampleApp.do_user_assertion
        # We don't add PAI for re-REGISTER, so 401 will be replied, and after it let's
        # revoke the current user assertion (will be re-added upon REGISTER with credentials).
        ::OverSIP::Modules::UserAssertion.revoke_assertion response
      end
    end

    proxy.route request
    return

  else

    log_info "method #{request.sip_method} not implemented => 501"
    request.reply 501, "Not Implemented"
    return

  end

end


# This method is called when a client initiates a SIP TLS handshake.
def (OverSIP::SipEvents).on_client_tls_handshake connection, pems

  log_info "validating TLS connection from IP #{connection.remote_ip} and port #{connection.remote_port}"

  cert, validated, tls_error, tls_error_string = ::OverSIP::TLS.validate pems
  identities = ::OverSIP::TLS.get_sip_identities cert

  if validated
    log_info "client provides a valid TLS certificate with SIP identities #{identities}"
  else
    log_notice "client provides an invalid TLS certificate with SIP identities #{identities} (TLS error: #{tls_error.inspect}, description: #{tls_error_string.inspect})"
    #connection.close
  end

end


# This method is called when conntacting a SIP TLS server and the TLS handshake takes place.
def (OverSIP::SipEvents).on_server_tls_handshake connection, pems

  log_info "validating TLS connection to IP #{connection.remote_ip} and port #{connection.remote_port}"

  cert, validated, tls_error, tls_error_string = ::OverSIP::TLS.validate pems
  identities = ::OverSIP::TLS.get_sip_identities cert

  if validated
    log_info "server provides a valid TLS certificate with SIP identities #{identities}"
  else
    log_notice "server provides an invalid TLS certificate with SIP identities #{identities} (TLS error: #{tls_error.inspect}, description: #{tls_error_string.inspect})"
    #connection.close
  end

end
