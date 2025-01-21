package Check::NetworkSpans;

use 5.006;
use strict;
use warnings;
use Rex::Commands::Gather;
use Regexp::IPv4 qw($IPv4_re);
use Regexp::IPv6 qw($IPv6_re);
use Scalar::Util qw(looks_like_number);
use File::Temp   qw/ tempdir /;
use String::ShellQuote;
use JSON;

=head1 NAME

Check::NetworkSpans - See if bidirectional traffic is being seen on the spans.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use Check::NetworkSpans;

    my $span_checker = Check::NetworkSpans->new();

=head1 METHODS

=head2 new

Initiates the object.

    - spans :: A array of arrays. Each sub array is a list of interfaces
            to check. If not defined it will check all interfaces and treat
            them as one span.
        - Default :: undef

    - ignore_IPs :: A array of IPs to ignore.
        - Default :: undef

    - auto_ignore :: If true, then will ignore all IP on that machine. Only
            for the first IP of the interface.
        - Default :: 1

    - packets :: Number of packets to gather for a interface for checking.
        - Default :: 10000

    - duration :: Number of seconds to limit the run to.
        - Default :: 120

    - ports :: Common ports to look for. Anything here will override the defaults.
        - Default :: [ 22, 53, 80, 88, 135, 389, 443, 445, 3389, 3306, 5432 ]

    - additional_ports :: Additional ports to look for.
        - Default :: [ ]

    - span_names :: Optional name for spans. Name corresponds to index of spans array.
        - Default :: [ ]

    my $span_checker = Check::NetworkSpans->new(
        spans                       => \@spans,
        ignore_IPs                  => \@ignore_IPs,
        auto_ignore                 => $auto_ignore,
        packets                     => $packets,
        duration                    => $duration,
        ports                       => \@ports,
        additional_ports            => \@additional_ports,
		no_packets                  => 2,
		no_packets_to_ignore        => {},
		low_packets                 => 1,
		low_packets_to_ignore       => {},
		no_streams                  => 2,
		no_streams_to_ignore        => {},
		missing_interface           => 3,
		missing_interface_to_ignore => {},
    );

=cut

sub new {
	my ( $blank, %opts ) = @_;

	# ensure spans is defined and an array
	if ( !defined( $opts{spans} ) ) {
		die('"spans" is undef');
	} elsif ( ref( $opts{spans} ) ne 'ARRAY' ) {
		die( '"spans" is defined and is ref "' . ref( $opts{spans} ) . '" instead of ARRAY' );
	}

	my $self = {
		ignore_IPs                  => [],
		spans                       => [],
		interfaces                  => [],
		packets                     => 10000,
		duration                    => 120,
		warnings                    => [],
		ports                       => [],
		ports_check                 => {},
		span_names                  => [],
		no_packets                  => 2,
		no_packets_to_ignore        => {},
		low_packets                 => 1,
		low_packets_to_ignore       => {},
		no_streams                  => 2,
		no_streams_to_ignore        => {},
		down_interface              => 2,
		down_interfaces_to_ignore   => {},
		missing_interface           => 3,
		missing_interface_to_ignore => {},
		interfaces_missing          => [],
		interfaces_down             => {},
		port_check                  => 1,
		port_check_to_ignore        => {},
		debug                       => $opts{debug},
	};
	bless $self;

	# suck in alert handling stuff
	my @alerts = ( 'no_packets', 'low_packets', 'no_streams', 'down_interface', 'missing_interface', 'port_check' );
	foreach my $alert_type (@alerts) {
		if ( defined( $opts{$alert_type} ) ) {
			if ( ref( $opts{$alert_type} ) ne '' ) {
				die( '$opts{' . $alert_type . '} should be ref "" and not ' . ref( $opts{$alert_type} ) );
			}
			if (   $opts{$alert_type} eq '0'
				|| $opts{$alert_type} eq '1'
				|| $opts{$alert_type} eq '2'
				|| $opts{$alert_type} eq '3' )
			{
				die( '$opts{' . $alert_type . '} should be either 0, 1, 2, or 3 and not ' . $opts{$alert_type} );
			}

		} ## end if ( defined( $opts{$alert_type} ) )
		if ( defined( $opts{ $alert_type . '_to_ignore' } ) ) {
			if ( ref( $opts{ $alert_type . '_to_ignore' } ) ne 'ARRAY' ) {
				die(      '$opts{'
						. $alert_type
						. '_to_ignore} should be ref ARRAY and not '
						. ref( $opts{ $alert_type . '_to_ignore' } ) );
			}
			foreach my $to_ignore ( @{ $opts{ $alert_type . '_to_ignore' } } ) {
				$self->{ $alert_type . '_to_ignore' }{$to_ignore} = 1;
			}
		} ## end if ( defined( $opts{ $alert_type . '_to_ignore'...}))
	} ## end foreach my $alert_type (@alerts)

	# get span_names and ensure it is a array
	if ( defined( $opts{span_names} ) && ref( $opts{span_names} ) eq 'ARRAY' ) {
		$self->{span_names} = $opts{span_names};
	} elsif ( defined( $opts{span_names} ) && ref( $opts{span_names} ) ne 'ARRAY' ) {
		die( '$opts{span_names} ref is not ARRAY, but "' . ref( $opts{span_names} ) . '"' );
	}

	# get packet info and do a bit of sanity checking
	if ( defined( $opts{packets} ) && looks_like_number( $opts{packets} ) ) {
		if ( $opts{packets} < 1 ) {
			die( '$opts{packets} is ' . $opts{packets} . ' which is less than 1' );
		}
		$self->{packets} = $opts{packets};
	} elsif ( defined( $opts{packets} ) && !looks_like_number( $opts{packets} ) ) {
		die('$opts{packets} is defined and not a number');
	}

	# if ports is set, ensure it is a array and if so process it
	if ( defined( $opts{ports} ) && ref( $opts{ports} ) ne 'ARRAY' ) {
		die( '"ports" is defined and is ref "' . ref( $opts{ports} ) . '" instead of ARRAY' );
	} elsif ( defined( $opts{ports} ) && ref( $opts{ports} ) eq 'ARRAY' && defined( $opts{ports}[0] ) ) {
		foreach my $port ( @{ $opts{ports} } ) {
			if ( ref($port) ne '' ) {
				die( 'Values for the array ports must be ref type ""... found "' . ref($port) . '"' );
			} elsif ( !looks_like_number($port) ) {
				die(      'Values for the array ports must be numberic... found "'
						. $port
						. '", which does not appear to be' );
			}
			push( @{ $self->{ports} }, $port );
		} ## end foreach my $port ( @{ $opts{ports} } )
	} else {
		# defaults if we don't have ports
		push( @{ $self->{ports} }, 22, 53, 80, 88, 135, 389, 443, 445, 3389, 3306, 5432 );
	}

	# if additional_ports is set, ensure it is a array and if so process it
	if ( defined( $opts{additional_ports} ) && ref( $opts{additional_ports} ) ne 'ARRAY' ) {
		die( '"additional_ports" is defined and is ref "' . ref( $opts{additional_ports} ) . '" instead of ARRAY' );
	} elsif ( defined( $opts{additional_ports} )
		&& ref( $opts{additional_ports} ) eq 'ARRAY'
		&& defined( $opts{additional_ports}[0] ) )
	{
		foreach my $port ( @{ $opts{additional_ports} } ) {
			if ( ref($port) ne '' ) {
				die( 'Values for the array additional_ports must be ref type ""... found "' . ref($port) . '"' );
			} elsif ( !looks_like_number($port) ) {
				die(      'Values for the array additional_ports must be numberic... found "'
						. $port
						. '", which does not appear to be' );
			}
			push( @{ $self->{ports} }, $port );
		} ## end foreach my $port ( @{ $opts{additional_ports} })
	} ## end elsif ( defined( $opts{additional_ports} ) &&...)

	if ( defined( $opts{duration} ) && looks_like_number( $opts{duration} ) ) {
		$self->{duration} = $opts{duration};
	}

	my $interfaces = network_interfaces;
	# make sure each specified interface exists
	foreach my $span ( @{ $opts{spans} } ) {
		if ( ref($span) ne 'ARRAY' ) {
			die( 'Values for spans should be a array of interface names... not ref "' . ref($span) . '"' );
		}
		my $new_span = [];
		if ( defined( $span->[0] ) ) {
			foreach my $interface ( @{$span} ) {
				if ( ref($interface) ne '' ) {
					die( 'interface values in span must be of ref type "" and not ref ' . ref($interface) );
				} elsif ( !defined( $interfaces->{$interface} ) ) {
					push( @{ $self->{interfaces_missing} }, $interface );
				} else {
					push( @{ $self->{interfaces} }, $interface );
					push( @{$new_span},             $interface );
				}
			} ## end foreach my $interface ( @{$span} )
		} ## end if ( defined( $span->[0] ) )

		push( @{ $self->{spans} }, $new_span );
	} ## end foreach my $span ( @{ $opts{spans} } )

	# ensure all the ignore IPs are actual IPs
	if ( defined( $opts{ignore_IPs} ) ) {
		if ( ref( $opts{ignore_IPs} ) ne 'ARRAY' ) {
			die( '"ignore_IPs" is defined and is ref "' . ref( $opts{ignore_IPs} ) . '" instead of ARRAY' );
		}

		foreach my $ip ( @{ $opts{ignore_IPs} } ) {
			if ( $ip !~ /^$IPv6_re$/ && $ip !~ /^$IPv4_re$/ ) {
				die( '"' . $ip . '" does not appear to be a IPv4 or IPv6 IP' );
			}
			push( @{ $self->{ignore_IPs} }, $ip );
		}
	} ## end if ( defined( $opts{ignore_IPs} ) )

	if ( $opts{auto_ignore} ) {
		foreach my $interface ( keys( %{$interfaces} ) ) {
			if (
				defined( $interfaces->{$interface}{ip} )
				&& (   $interfaces->{$interface}{ip} =~ /^$IPv6_re$/
					|| $interfaces->{$interface}{ip} =~ /^$IPv4_re$/ )
				)
			{
				push( @{ $self->{ignore_IPs} }, $interfaces->{$interface}{ip} );
			}
		} ## end foreach my $interface ( keys( %{$interfaces} ) )
	} ## end if ( $opts{auto_ignore} )

	# put together list of ports to help
	foreach my $ports ( @{ $self->{ports} } ) {
		$self->{ports_check}{$ports} = 1;
	}

	return $self;
} ## end sub new

=head2 check

Runs the check. This will call helper-check_networkspans, which will call tshark
to perform the capture.

=cut

sub check {
	my $self = $_[0];

	$ENV{CHECK_NETWORKSPANS_INTERFACES} = join( ' ', @{ $self->{interfaces} } );
	$ENV{CHECK_NETWORKSPANS_DURATION}   = $self->{duration};
	$ENV{CHECK_NETWORKSPANS_PACKETS}    = $self->{packets};

	my $filter = '';
	if ( $self->{ignore_IPs}[0] ) {
		my $ignore_IPs_int = 0;
		while ( defined( $self->{ignore_IPs}[$ignore_IPs_int] ) ) {
			if ( $ignore_IPs_int > 0 ) {
				$filter = $filter . ' and';
			}
			$filter = $filter . ' not host ' . $self->{ignore_IPs}[$ignore_IPs_int];

			$ignore_IPs_int++;
		}
	} ## end if ( $self->{ignore_IPs}[0] )
	$filter =~ s/^ //;
	$ENV{CHECK_NETWORKSPANS_FILTER} = $filter;

	my $dir = tempdir( CLEANUP => 1 );
	$ENV{CHECK_NETWORKSPANS_DIR} = $dir;
	chdir($dir);

	my $output = `helper-check_networkspans`;

	# process each PCAP into a hash
	my $pcap_data = {};
	foreach my $interface ( @{ $self->{interfaces} } ) {
		my $qinterface = shell_quote($interface);
		if ( -f $interface . '.pcap' ) {
			my $pcap_json = `tshark -r $qinterface.pcap -T json -J "ip eth tcp udp" 2> /dev/null`;
			eval {
				my $tmp = decode_json($pcap_json);
				$pcap_data->{$interface} = $tmp;
			};
			if ($@) {
				push( @{ $self->{warnings} }, 'Failed to parse PCAP for interface "' . $interface . '"' );
			}
		} else {
			push( @{ $self->{warnings} }, 'Failed capture PCAP for "' . $interface . '"' );
		}
	} ## end foreach my $interface ( @{ $self->{interfaces} ...})

	my $connections            = {};
	my $per_port_connections   = {};
	my $interface_packet_count = {};
	foreach my $interface ( @{ $self->{interfaces} } ) {
		$connections->{$interface}          = {};
		$per_port_connections->{$interface} = 0;
		if ( defined( $pcap_data->{$interface} ) && ref( $pcap_data->{$interface} ) eq 'ARRAY' ) {
			$interface_packet_count->{$interface} = $#{ $pcap_data->{$interface} } + 1;

			# process each packet for
			foreach my $packet ( @{ $pcap_data->{$interface} } ) {
				eval {
					if (   defined( $packet->{_source} )
						&& defined( $packet->{_source}{layers} )
						&& defined( $packet->{_source}{layers}{eth} ) )
					{
						my $name     = '';
						my $proto    = '';
						my $dst_ip   = '';
						my $dst_port = '';
						my $src_ip   = '';
						my $src_port = '';

						# used for skipping odd broken packets or and broad cast stuff
						my $add_it = 1;

						if ( defined( $packet->{_source}{layers}{udp} ) ) {
							$proto = 'udp';
							if ( defined( $packet->{_source}{layers}{udp}{'udp.dstport'} ) ) {
								$dst_port = $packet->{_source}{layers}{udp}{'udp.dstport'};
							} else {
								$add_it = 0;
							}
							if ( defined( $packet->{_source}{layers}{udp}{'udp.srcport'} ) ) {
								$src_port = $packet->{_source}{layers}{udp}{'udp.srcport'};
							} else {
								$add_it = 0;
							}
						} ## end if ( defined( $packet->{_source}{layers}{udp...}))
						if ( defined( $packet->{_source}{layers}{tcp} ) ) {
							$proto = 'tcp';
							if ( defined( $packet->{_source}{layers}{tcp}{'tcp.dstport'} ) ) {
								$dst_port = $packet->{_source}{layers}{tcp}{'tcp.dstport'};
							} else {
								$add_it = 0;
							}
							if ( defined( $packet->{_source}{layers}{tcp}{'tcp.srcport'} ) ) {
								$src_port = $packet->{_source}{layers}{tcp}{'tcp.srcport'};
							} else {
								$add_it = 0;
							}
						} ## end if ( defined( $packet->{_source}{layers}{tcp...}))
						if (   defined( $packet->{_source}{layers}{ip} )
							&& defined( $packet->{_source}{layers}{ip}{'ip.src'} ) )
						{
							$src_ip = $packet->{_source}{layers}{ip}{'ip.src'};
						} else {
							$add_it = 0;
						}
						if (   defined( $packet->{_source}{layers}{ip} )
							&& defined( $packet->{_source}{layers}{ip}{'ip.dst'} ) )
						{
							$dst_ip = $packet->{_source}{layers}{ip}{'ip.dst'};
						} else {
							$add_it = 0;
						}

						# save the packet to per port info
						if ( $add_it && defined( $self->{ports_check}{$dst_port} ) ) {
							$per_port_connections->{$interface}++;
						}
						if ( $add_it && defined( $self->{ports_check}{$src_port} ) ) {
							$per_port_connections->{$interface}++;
						}

						if ($add_it) {
							$name = $proto . '-' . $src_ip . '%' . $src_port . '-' . $dst_ip . '%' . $dst_port;
							$connections->{$interface}{$name} = $packet;
						}
					} ## end if ( defined( $packet->{_source} ) && defined...)
				};
			} ## end foreach my $packet ( @{ $pcap_data->{$interface...}})
		} else {
			$interface_packet_count->{$interface} = 0;
		}
	} ## end foreach my $interface ( @{ $self->{interfaces} ...})

	my $results = {
		'oks'       => [],
		'warnings'  => [],
		'criticals' => [],
		'errors'    => [],
		'ignored'   => [],
		status      => 0,
	};

	# check each span for bi directional traffic traffic
	my $span_int = 0;
	foreach my $span ( @{ $self->{spans} } ) {
		my $count = 0;
		foreach my $interface ( @{$span} ) {
			# process each connection for the interface looking for matches
			foreach my $packet_name ( keys( %{ $connections->{$interface} } ) ) {
				my $packet = $connections->{$interface}{$packet_name};
				if (
					(
						   defined( $packet->{_source}{layers}{ip} )
						&& defined( $packet->{_source}{layers}{ip}{'ip.dst'} )
						&& defined( $packet->{_source}{layers}{ip}{'ip.src'} )

					)
					&& (
						(
							   defined( $packet->{_source}{layers}{tcp} )
							&& defined( $packet->{_source}{layers}{tcp}{'tcp.dstport'} )
							&& defined( $packet->{_source}{layers}{tcp}{'tcp.srcport'} )
						)
						|| (   defined( $packet->{_source}{layers}{udp} )
							&& defined( $packet->{_source}{layers}{udp}{'tcp.dstport'} )
							&& defined( $packet->{_source}{layers}{udp}{'tcp.srcport'} ) )
					)
					)
				{
					my $name     = '';
					my $dst_port = '';
					my $src_port = '';
					my $proto    = '';
					my $dst_ip   = $packet->{_source}{layers}{ip}{'ip.dst'};
					my $src_ip   = $packet->{_source}{layers}{ip}{'ip.src'};

					if ( defined( $packet->{_source}{layers}{udp} ) ) {
						$proto = 'udp';
						if ( defined( $packet->{_source}{layers}{udp}{'udp.dstport'} ) ) {
							$dst_port = $packet->{_source}{layers}{udp}{'udp.dstport'};
						}
						if ( defined( $packet->{_source}{layers}{udp}{'udp.srcport'} ) ) {
							$src_port = $packet->{_source}{layers}{udp}{'udp.srcport'};
						}

					} ## end if ( defined( $packet->{_source}{layers}{udp...}))
					if ( defined( $packet->{_source}{layers}{tcp} ) ) {
						$proto = 'tcp';
						if ( defined( $packet->{_source}{layers}{tcp}{'tcp.dstport'} ) ) {
							$dst_port = $packet->{_source}{layers}{tcp}{'tcp.dstport'};
						}
						if ( defined( $packet->{_source}{layers}{tcp}{'tcp.srcport'} ) ) {
							$src_port = $packet->{_source}{layers}{tcp}{'tcp.srcport'};
						}
					}

					$name = $proto . '-' . $dst_ip . '%' . $dst_port . '-' . $src_ip . '%' . $src_port;

					my $found_it = 0;
					foreach my $interface2 ( @{$span} ) {
						if ( defined( $connections->{$interface2}{$name} ) ) {
							$found_it = 1;
						}
					}

					if ($found_it) {
						$count++;
					}
				} ## end if ( ( defined( $packet->{_source}{layers}...)))
			} ## end foreach my $packet_name ( keys( %{ $connections...}))
		} ## end foreach my $interface ( @{$span} )

		# if count is less than one, then no streams were found
		if ( $count < 1 ) {
			my $level = 'oks';
			if ( $self->{no_streams} == 1 ) {
				$level = 'warnings';
			} elsif ( $self->{no_streams} == 2 ) {
				$level = 'criticals';
			} elsif ( $self->{no_streams} == 3 ) {
				$level = 'errors';
			}

			my $message = 'No TCP/UDP streams found for span ' . $self->get_span_name($span_int);

			if (   $self->{no_streams_to_ignore}{ $self->get_span_name_for_check($span_int) }
				|| $self->{no_streams_to_ignore}{ join( ',', @{$span} ) } )
			{
				push( @{ $results->{ignored} }, 'IGNORED - ' . $level . ' - ' . $message );
			} else {
				push( @{ $results->{$level} }, $message );
			}
		} ## end if ( $count < 1 )

		$span_int++;
	} ## end foreach my $span ( @{ $self->{spans} } )

	# ensure we got traffic on the specified ports
	$span_int = 0;
	foreach my $span ( @{ $self->{spans} } ) {
		my $ports_found = 0;
		foreach my $interface ( @{$span} ) {
			if ( $per_port_connections->{$interface} > 0 ) {
				$ports_found = 1;
			}
		}
		if ( !$ports_found ) {
			my $level = 'oks';
			if ( $self->{port_check} == 1 ) {
				$level = 'warnings';
			} elsif ( $self->{port_check} == 2 ) {
				$level = 'criticals';
			} elsif ( $self->{port_check} == 3 ) {
				$level = 'errors';
			}
			my $message
				= 'no packets for ports '
				. join( ',', @{ $self->{ports} } )
				. ' for span '
				. $self->get_span_name($span_int);

			if (   $self->{port_check_to_ignore}{ $self->get_span_name_for_check($span_int) }
				|| $self->{port_check_to_ignore}{ join( ',', @{$span} ) } )
			{
				push( @{ $results->{ignored} }, 'IGNORED - ' . $level . ' - ' . $message );
			} else {
				push( @{ $results->{$level} }, $message );
			}
		} ## end if ( !$ports_found )
		$span_int++;
	} ## end foreach my $span ( @{ $self->{spans} } )

	# check for interfaces with no packets
	$span_int = 0;
	foreach my $span ( @{ $self->{spans} } ) {
		foreach my $interface ( @{$span} ) {
			if ( $interface_packet_count->{$interface} == 0 ) {
				my $level = 'oks';
				if ( $self->{no_packets} == 1 ) {
					$level = 'warnings';
				} elsif ( $self->{no_packets} == 2 ) {
					$level = 'criticals';
				} elsif ( $self->{no_packets} == 3 ) {
					$level = 'errors';
				}
				my $message
					= 'interface ' . $interface . ' for span ' . $self->get_span_name($span_int) . ' has no packets';
				if ( defined( $self->{no_packets_to_ignore}{$interface} ) ) {
					push( @{ $results->{ignored} }, 'IGNORED - ' . $level . ' - ' . $message );
				} else {
					push( @{ $results->{$level} }, $message );
				}

			} ## end if ( $interface_packet_count->{$interface}...)
		} ## end foreach my $interface ( @{$span} )
		$span_int++;
	} ## end foreach my $span ( @{ $self->{spans} } )

	#check for low packet count on interfaces
	$span_int = 0;
	foreach my $span ( @{ $self->{spans} } ) {
		foreach my $interface ( @{$span} ) {
			if ( $interface_packet_count->{$interface} < $self->{packets} ) {
				my $level = 'oks';
				if ( $self->{low_packets} == 1 ) {
					$level = 'warnings';
				} elsif ( $self->{low_packets} == 2 ) {
					$level = 'criticals';
				} elsif ( $self->{low_packets} == 3 ) {
					$level = 'errors';
				}
				my $message
					= 'interface '
					. $interface
					. ' for span '
					. $self->get_span_name($span_int)
					. ' has a packet count of '
					. $interface_packet_count->{$interface}
					. ' which is less than the required '
					. $self->{packets};
				if ( defined( $self->{low_packets_to_ignore}{$interface} ) ) {
					push( @{ $results->{ignored} }, 'IGNORED - ' . $level . ' - ' . $message );
				} else {
					push( @{ $results->{$level} }, $message );
				}
			} ## end if ( $interface_packet_count->{$interface}...)
		} ## end foreach my $interface ( @{$span} )
		$span_int++;
	} ## end foreach my $span ( @{ $self->{spans} } )

	# check for missing interfaces
	if (   $#{ $self->{interfaces_missing} } >= 0
		&& $self->{missing_interface} > 0 )
	{
		my $level = 'oks';
		if ( $self->{missing_interface} == 1 ) {
			$level = 'warnings';
		} elsif ( $self->{missing_interface} == 2 ) {
			$level = 'criticals';
		} elsif ( $self->{missing_interface} == 3 ) {
			$level = 'errors';
		}

		# sort the missing interfaces into ignored and not ignored
		my @ignored_interfaces;
		my @missing_interfaces;
		foreach my $interface ( @{ $self->{interfaces_missing} } ) {
			if ( defined( $self->{missing_interface_to_ignore}{$interface} ) ) {
				push( @ignored_interfaces, $interface );
			} else {
				push( @missing_interfaces, $interface );
			}
		}

		# handle ignored missing interfaces
		if ( defined( $ignored_interfaces[0] ) ) {
			my $message = 'missing interfaces... ' . join( ',', @ignored_interfaces );
			push( @{ $results->{ignored} }, 'IGNORED - ' . $level . ' - ' . $message );
		}

		# handle not ignored missing interfaces
		if ( defined( $ignored_interfaces[0] ) ) {
			my $message = 'missing interfaces... ' . join( ',', @missing_interfaces );
			push( @{ $results->{$level} }, $message );
		}
	} ## end if ( $#{ $self->{interfaces_missing} } >= ...)

	# sets the final status
	# initially set to 0, OK
	if ( defined( $results->{errors}[0] ) ) {
		$results->{status} = 3;
	} elsif ( defined( $results->{alerts}[0] ) ) {
		$results->{status} = 2;
	} elsif ( defined( $results->{warnings}[0] ) ) {
		$results->{status} = 1;
	}

	return $results;
} ## end sub check

=head2 get_span_name

Returns span name for display purposes.

=cut

sub get_span_name {
	my $self     = $_[0];
	my $span_int = $_[1];

	if ( !defined($span_int) ) {
		return 'undef';
	}

	if ( !defined( $self->{spans}[$span_int] ) ) {
		return 'undef';
	}

	my $name = join( ',', @{ $self->{spans}[$span_int] } );
	if ( defined( $self->{span_names}[$span_int] ) && $self->{span_names}[$span_int] ne '' ) {
		$name = $self->{span_names}[$span_int] . '(' . $name . ')';
	}

	return $name;
} ## end sub get_span_name

=head2 get_span_name_for_check

Returns span name for check purposes.

=cut

sub get_span_name_for_check {
	my $self     = $_[0];
	my $span_int = $_[1];

	if ( !defined($span_int) ) {
		return 'undef';
	}

	if ( !defined( $self->{spans}[$span_int] ) ) {
		return 'undef';
	}

	if ( defined( $self->{span_names}[$span_int] ) && $self->{span_names}[$span_int] ne '' ) {
		return $self->{span_names}[$span_int];
	}

	return join( ',', @{ $self->{spans}[$span_int] } );
} ## end sub get_span_name_for_check

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-check-networkspans at rt.cpan.org>, or through
the web interface at L<https://rt.cpan.org/NoAuth/ReportBug.html?Queue=Check-NetworkSpans>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Check::NetworkSpans


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<https://rt.cpan.org/NoAuth/Bugs.html?Dist=Check-NetworkSpans>

=item * CPAN Ratings

L<https://cpanratings.perl.org/d/Check-NetworkSpans>

=item * Search CPAN

L<https://metacpan.org/release/Check-NetworkSpans>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2024 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The GNU General Public License, Version 2, June 1991


=cut

1;    # End of Check::NetworkSpans
