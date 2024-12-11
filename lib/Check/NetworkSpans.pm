package Check::NetworkSpans;

use 5.006;
use strict;
use warnings;
use Rex::Commands::Gather;
use Regexp::IPv4 qw($IPv4_re);
use Regexp::IPv6 qw($IPv6_re);
use Scalar::Util qw(looks_like_number);
use File::Temp qw/ tempdir /;

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
        - Default :: 2000

    - duration :: Number of seconds to limit the run to.
        - Default :: 120

=cut

sub new {
	my ( $blank, %opts ) = @_;

	# ensure spans is defined and an array
	if ( !defined( $opts{spans} ) ) {
		die('"spans" is undef');
	} elsif ( ref( $opts{spans} ) ne 'ARRAY' ) {
		die( '"spans" is defined and is ref "' . ref( $opts{spans} ) . '" instead of ARRAY' );
	}

	my $self = { ignore_IPs => [], spans => [], interfaces=>[], packets=>2000, duration=>120 };
	bless $self;

	if (defined($opts{packets}) && looks_like_number($opts{packets})) {
		$self->{packets}=$opts{packets};
	}

	if (defined($opts{duration}) && looks_like_number($opts{duration})) {
		$self->{duration}=$opts{duration};
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
					die('"'.$interface.'" does not exist');
				}
				push(@{$self->{interfaces}}, $interface);
			}
		}

		push( @{ $self->{span} }, $span );
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
			if ( defined( $interface->{ip} )
				&& ( $interface->{ip} =~ /^$IPv6_re$/ || $interface->{ip} =~ /^$IPv4_re$/ ) )
			{
				push( @{ $self->{ignore_IPs} }, $interface->{ip} );
			}
		}
	}

	return $self;
} ## end sub new

=head2 check

=cut

sub check {
	my $self = $_[0];

	$ENV{CHECK_NETWORKSPANS_INTERFACES}=join(' ', @{$self->{interfaces}});
	$ENV{CHECK_NETWORKSPANS_DURATION}=$self->{duration};
	$ENV{CHECK_NETWORKSPANS_PACKETS}=$self->{packets};

	my $filter = '';
	if ($self->{ignore_IPs}[0]) {
		my $ignore_IPs_int=0;
		while (defined($self->{ignore_IPs}[$ignore_IPs_int])) {
			if ($ignore_IPs_int > 0) {
				$filter = $filter . ' and';
			}
			$filter = $filter . ' not host '.$self->{ignore_IPs}[$ignore_IPs_int];

			$ignore_IPs_int++;
		}
	}
	$ENV{CHECK_NETWORKSPANS_FILTER} = $filter;

	my $dir = tempdir( CLEANUP => 1 );
	$ENV{CHECK_NETWORKSPANS_DIR}=$dir;
	chdir($dir);

	my $output=`helper-check_networkspans`;

	
}

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
