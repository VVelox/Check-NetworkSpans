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

    my $span_checker = Check::NetworkSpans->new(
        spans            => \@spans,
        ignore_IPs       => \@ignore_IPs,
        auto_ignore      => $auto_ignore,
        packets          => $packets,
        duration         => $duration,
        ports            => \@ports,
        additional_ports => \@additional_ports,
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
		ignore_IPs  => [],
		spans       => [],
		interfaces  => [],
		packets     => 10000,
		duration    => 120,
		warnings    => [],
		ports       => [],
		ports_check => {},
	};
	bless $self;

	if ( defined( $opts{packets} ) && looks_like_number( $opts{packets} ) ) {
		$self->{packets} = $opts{packets};
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
		if ( defined( $span->[0] ) ) {
			foreach my $interface ( @{$span} ) {
				if ( ref($interface) ne '' ) {
					die( 'interface values in span must be of ref type "" and not ref ' . ref($interface) );
				} elsif ( !defined( $interfaces->{$interface} ) ) {
					die( '"' . $interface . '" does not exist' );
				}
				push( @{ $self->{interfaces} }, $interface );
			}
		} ## end if ( defined( $span->[0] ) )

		push( @{ $self->{spans} }, $span );
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
	foreach my $ports (@{ $self->{ports} }) {
		$self->{ports_check}{$ports}=0;
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

	my $connections = {};
	foreach my $interface ( @{ $self->{interfaces} } ) {
		$connections->{$interface}={};
		if ( defined( $pcap_data->{$interface} ) && ref( $pcap_data->{$interface} ) eq 'ARRAY' ) {
			# process each packet for
			foreach my $packet ( @{ $pcap_data->{$interface} } ) {
				eval {
					if (   defined( $packet->{_source} )
						&& defined( $packet->{_source}{layers} )
						&& defined( $packet->{_source}{layers}{eth} ) )
					{
						my $name = '';
						my $dst_port='';
						my $src_port='';
						if ( defined( $packet->{_source}{layers}{udp} ) ) {
							$name = $name . 'udp';
							if ( defined( $packet->{_source}{layers}{udp}{'udp.dstport'} ) ) {
								$dst_port=$packet->{_source}{layers}{udp}{'udp.dstport'};
							}
							if ( defined( $packet->{_source}{layers}{udp}{'udp.srcport'} ) ) {
								$src_port=$packet->{_source}{layers}{udp}{'udp.srcport'};
							}
						}
						if ( defined( $packet->{_source}{layers}{tcp} ) ) {
							$name = $name . 'tcp';
							if ( defined( $packet->{_source}{layers}{tcp}{'tcp.dstport'} ) ) {
								$dst_port=$packet->{_source}{layers}{tcp}{'tcp.dstport'};
							}
							if ( defined( $packet->{_source}{layers}{tcp}{'tcp.srcport'} ) ) {
								$src_port=$packet->{_source}{layers}{tcp}{'tcp.srcport'};
							}
						}
						if ( defined(
									 $packet->{_source}{layers}{ip}) &&
							 defined($packet->{_source}{layers}{ip}{'ip.src'})
							) {
							$name = $name . '-'.$packet->{_source}{layers}{ip}{'ip.src'}.'%'.$src_port;
						}
						if ( defined(
									 $packet->{_source}{layers}{ip}) &&
							 defined($packet->{_source}{layers}{ip}{'ip.dst'})
							) {
							$name = $name .'-'. $packet->{_source}{layers}{ip}{'ip.dst'}.'%'.$dst_port;
						}

						$connections->{$interface}{$name}=$packet;
					} ## end if ( defined( $packet->{_source} ) && defined...)
				};
			} ## end foreach my $packet ( @{ $pcap_data->{$interface...}})
		} ## end if ( defined( $pcap_data->{$interface} ) &&...)
	} ## end foreach my $interface ( @{ $self->{interfaces} ...})

	# holds a count of packets found on the span
	my $span_check={};
	# check each span for traffic
	foreach my $span (@{$self->{spans}}) {
		my $span_name=join(',', @{$span});
		$span_check->{$span_name}=0;
		foreach my $interface (@{$span}) {
			# process each connection for the interface looking for matches
			foreach my $packet (keys(%{$connections->{$interface}})) {
				if ( (
					  defined( $packet->{_source}{layers}{tcp} ) &&
					  defined( $packet->{_source}{layers}{tcp}{'tcp.dstport'} ) &&
					  defined( $packet->{_source}{layers}{tcp}{'tcp.srcport'} )
					  ) || (
							defined( $packet->{_source}{layers}{udp} ) &&
							defined( $packet->{_source}{layers}{udp}{'tcp.dstport'} ) &&
							defined( $packet->{_source}{layers}{udp}{'tcp.srcport'} )
					  )
					  ) {
					my $name = '';
					my $dst_port='';
					my $src_port='';
				}
			}
		}
	}
} ## end sub check

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
