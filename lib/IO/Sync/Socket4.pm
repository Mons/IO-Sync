package IO::Sync::Socket4;

use strict;
BEGIN {
	require "AnyEvent/constants.pl";
}
use AnyEvent::Util qw(fh_nonblocking);
use Socket qw( AF_INET AF_UNIX SOCK_STREAM SOCK_DGRAM SOL_SOCKET SO_REUSEADDR );
use AnyEvent::Socket ();
use Time::HiRes 'time';
use Net::ADNS;
use Carp;
use uni::perl ':dumper';

### Utils ###

BEGIN{ *fhnb = \&AnyEvent::Util::fh_nonblocking };

sub AF_INET6 () { 0 }


our %PROTOCOL = ( ipv4 => 1 );

# Completely derived from AnyEvent::Socket-v7.02

sub resolve_sockaddr($$$$$;$) {
   my ($node, $service, $proto, $family, $type, $timeout) = @_;
   $timeout ||= 2;
   my $till = time + $timeout;

   if ($node eq "unix/") {
      return if $family || $service !~ /^\//; # no can do

      return [AF_UNIX, defined $type ? $type : SOCK_STREAM, 0, Socket::pack_sockaddr_un $service];
   }

   unless (AF_INET6) {
      $family != 6 or return;
      $family = 4;
   }

   return if $family == 4 && !$PROTOCOL{ipv4};
   return if $family == 6 && !$PROTOCOL{ipv6};

   $family ||= 4 unless $PROTOCOL{ipv6};
   $family ||= 6 unless $PROTOCOL{ipv4};

   $proto ||= "tcp";
   $type  ||= $proto eq "udp" ? SOCK_DGRAM : SOCK_STREAM;

   my $proton = AnyEvent::Socket::getprotobyname $proto
      or Carp::croak "$proto: protocol unknown";

   my $port;

   if ($service =~ /^(\S+)=(\d+)$/) {
      ($service, $port) = ($1, $2);
   } elsif ($service =~ /^\d+$/) {
      ($service, $port) = (undef, $service);
   } else {
      $port = (getservbyname $service, $proto)[2]
              or Carp::croak "$service/$proto: service unknown";
   }

   # resolve a records / provide sockaddr structures
   
   $node = AnyEvent::Util::idn_to_ascii $node if $node =~ /[^\x00-\x7f]/;

   # try srv records, if applicable
   my @target;
   if ($node eq "localhost") {
      @target = (["127.0.0.1", $port], ["::1", $port]);
   } elsif (defined $service && !AnyEvent::Socket::parse_address $node) {
      my @srv = IO::Sync::DNS::srv $service, $proto, $node, $till - time;
      
         if (@srv) {
            # the only srv record has "." ("" here) => abort
            $srv[0][2] ne "" || $#srv
               or return;

            # use srv records then
            @target = (
               map ["$_->[3].", $_->[2]],
                  grep $_->[3] ne ".",
                     @srv
            );
         } else {
            # no srv records, continue traditionally
            @target = ([$node, $port]);
         }
   } else {
      # most common case
      @target = ([$node, $port]);
   }
   
   #warn "resolve ".dumper \@target;

      my @res;

      for my $idx (0 .. $#target) {
         my ($node, $port) = @{ $target[$idx] };

         if (my $noden = AnyEvent::Socket::parse_address $node) {
            my $af = AnyEvent::Socket::address_family $noden;

            if ($af == AF_INET && $family != 6) {
               push @res, [$idx, "ipv4", [AF_INET, $type, $proton,
                           AnyEvent::Socket::pack_sockaddr $port, $noden]]
            }

            if ($af == AF_INET6 && $family != 4) {
               push @res, [$idx, "ipv6", [AF_INET6, $type, $proton,
                           AnyEvent::Socket::pack_sockaddr $port, $noden]]
            }
         } else {
            $node =~ y/A-Z/a-z/;

            #my $hosts = $HOSTS{$node};

            # a records
            if ($family != 6) {
               my @rr = IO::Sync::DNS::a $node, $till - time;
               
               push @res, [$idx, "ipv4", [AF_INET , $type, $proton, AnyEvent::Socket::pack_sockaddr $port, AnyEvent::Socket::parse_ipv4 $_]]
                  for @rr;

               #   # dns takes precedence over hosts
               #   _load_hosts_unless {
               #      push @res,
               #         map [$idx, "ipv4", [AF_INET , $type, $proton, pack_sockaddr $port, $_]],
               #            @{ $HOSTS{$node}[0] };
               #   } $cv, @_;
            }

            # aaaa records not supported yet
            if ($family != 4) {
                my @rr = IO::Sync::DNS::aaaa $node, $till - time;
                push @res, [$idx, "ipv6", [AF_INET6, $type, $proton, pack_sockaddr $port, parse_ipv6 $_]]
                  for @rr;

            #      _load_hosts_unless {
            #         push @res,
            #            map [$idx + 0.5, "ipv6", [AF_INET6, $type, $proton, pack_sockaddr $port, $_]],
            #               @{ $HOSTS{$node}[1] }
            #      } $cv, @_;
            }
         }
      }
      #warn dumper \@res;
      return
            map $_->[2],
            sort {
               #$AnyEvent::PROTOCOL{$b->[1]} <=> $AnyEvent::PROTOCOL{$a->[1]}
               $b->[1] cmp $a->[1]
               or
               $a->[0] <=> $b->[0]
            }
            @res
   
}


sub fhwait($$$) {
	my ($fh,$type,$timeout) = @_;
	return if $timeout < 0;
	my $in = '';
	vec( $in, fileno( $fh ), 1 ) = 1;
	if ( $type eq 'r' ) {
		select( $in,'',$in,$timeout );
	}
	elsif ($type eq 'w') {
		select( '',$in,$in,$timeout );
	}
	else {
		select( $in,$in,$in,$timeout );
	}
}

=for rem
			given ($i->[0]) {
				when ('line') {
					#warn "parse as line";
					if ((my $idx = index( $self->{rbuf}, "\n" )) > -1) {
						my $s = substr($self->{rbuf},0,$idx+1,'');
						#warn dumper $s;
						my $nl = substr($s,-2,1) eq "\015" ? substr( $s,-2,2,'' ) : substr($s,-1,1,'');
						#warn "index match $idx ".dumper $nl;
						$i->[1]( $self, $s, $nl );
						next LOOP;
					} else {
						last LOOP;
					}
				}
				when ('regex') {
					#warn "parse as regex $i->[1] ";#.dumper( $self->{rbuf} );
					if ( $self->{rbuf} =~ $i->[1] ) {
						#warn "regex match $+[0] ";
						$i->[2]( $self, substr($self->{rbuf},0,$+[0],'') );
						next LOOP;
					} else {
						last LOOP;
					}
				}
				when ('chunk') {
					#warn "parse as chunk $i->[1]";
					if ( $i->[1] < $len ) {
						$i->[2]( $self, substr($self->{rbuf},0,$i->[1],'') );
						next LOOP;
					} else {
						last LOOP;
					}
				}
				when ('all') {
					#warn "pass all (eof=$self->{_eof})";
					if ($len > 0) {
						my $rr = delete $self->{rbuf};
						$i->[1]( $self, $rr );
						next LOOP;
					} else {
						warn "no data for $_";
						last LOOP;
					}
				}
				default {
					die "Unknown : $_";
					last LOOP;
				}
				#$self->_error( Errno::EPIPE ) if $self->{_eof};
				#last LOOP;

=cut

sub fhread($$;$) {
	my ($fh,$size,$timeout) = @_;
	my $till = time + $timeout;
	fh_nonblocking $fh, 1;
	my $buf;
	my $offset = 0;
	my $rd;
	while () {
		warn "read... to $offset";
		$rd = sysread $fh, $buf, $size - $offset, $offset;
		return do{ fhnb $fh,0; \$buf } if length $buf == $size;
		if (defined $rd) {
			if ($rd == 0) {
				# EOF
				warn "EOF";
				fhnb $fh,0;
				$! = Errno::ECONNRESET;
				return \$buf;
			} else {
				warn "Partial read $rd";
				$offset = length $buf;
				fhwait($fh, r => $till - time);
				return do{ fhnb $fh,0; $! = Errno::ETIMEDOUT; \$buf } if time > $till;
				next;
			}
		}
		elsif ( $! == Errno::EAGAIN or $! == Errno::EINTR or $! == AnyEvent::Util::WSAEWOULDBLOCK ) {
			warn "No read ($!)";
			$offset = length $buf;
			fhwait($fh, r => $till - time);
			return do{ fhnb $fh,0; $! = Errno::ETIMEDOUT; \$buf } if time > $till;
			next;
		}
		else {
			warn "read error: $! ($rd)";
			fhnb $fh,0;
			return;
		}
	}
}

sub fhrecv($$$;$) {
	my ($fh,$size, $flags, $timeout) = @_;
	$timeout ||= 5;
	my $till = time + $timeout;
	fh_nonblocking $fh, 1;
	my $rd;
	my $buf;
	while () {
		$rd = recv $fh,$buf,$size,$flags;
		if (defined $rd) {
			fhnb $fh,0;
			return $buf
		}
		elsif ( $! == Errno::EAGAIN or $! == Errno::EINTR or $! == AnyEvent::Util::WSAEWOULDBLOCK ) {
			warn "Wait for recv";
			fhwait($fh, r => $till - time);
			return do{ fhnb $fh,0; $! = Errno::ETIMEDOUT; () } if time > $till;
			next;
		}
		else {
			warn "Fatal error on recv: $!";
			fhnb $fh,0;
			return;
		}
	}
	
}

sub fhwrite($$;$) {
	my ($fh,$buf,$timeout) = @_;
	$timeout ||= 5;
	my $till = time + $timeout;
	fh_nonblocking $fh, 1;
	my $offset = 0;
	my $wr;
	while () {
		$wr = syswrite $fh,$buf;
		return do{ fhnb $fh,0; length $buf } if $offset + $wr == length $buf;
		if ( defined $wr or $! == Errno::EAGAIN or $! == Errno::EINTR or $! == AnyEvent::Util::WSAEWOULDBLOCK ) {
			warn "Partial write";
			$offset += $wr;
			fhwait($fh, w => $till - time);
			return do{ fhnb $fh,0; $! = Errno::ETIMEDOUT; () } if time > $till;
			next;
		}
		else {
			fhnb $fh,0;
			return;
		}
	}
}

### Utils ###

sub new {
	return bless {}, shift;
}

sub tcp_connect ($$;$) :method {
	my ($host,$port) = splice @_,0,2;
	my $timeout = shift || 3;
	my $till = time + $timeout;
	
	                          # my ($node, $service, $proto, $family, $type, $timeout) = @_;
	my @resolved = resolve_sockaddr($host, $port, 0, 0, undef, $timeout ) or return;
	for (@resolved) {
		my ($domain, $type, $proto, $sockaddr) = @$_;
		socket my $fh, $domain, $type, $proto or die "socket failed: $!";
		if ($domain == AF_INET) {
			setsockopt $fh, SOL_SOCKET, SO_REUSEADDR, 1
			or Carp::croak "tcp_connect/so_reuseaddr: $!"
		}
		fhnb $fh, 1;
		connect $fh, $sockaddr and do { fhnb $fh, 0; return $fh };
		fhwait $fh, w => $till - time or do { $! = Errno::ETIMEDOUT; die "connect wait failed: $!" };
		if (my $sin = getpeername $fh) {
			my ($inport, $inhost) = AnyEvent::Socket::unpack_sockaddr $sin;
			$inhost = AnyEvent::Socket::format_address $inhost;
			warn "ok $inhost:$inport";
			
			fhnb $fh, 0;
			return $fh;
		}
		elsif ($! == Errno::ENOTCONN) {
			sysread $fh, my $buf, 1;
			my $e = $!;
			die "connect failed: $!";
		}
		else {
			die "connect failed: $!";
		}
	}
	die "Can't connect";
}

sub rawconnect :method {
	my $self = shift;
	my ($host,$port) = splice @_,0,2;
	my $addr;
	if (length $host == 4) {
		$addr = $host;
		$host = AnyEvent::Socket::format_address $addr;
	}
	elsif ( $addr = AnyEvent::Socket::parse_ipv4($host) ) {
	
	}
	else { croak "Need IP Address"; }
	#my ($self, $addr, $port, $timeout) = @_;
	my $timeout = 5;
	my $start = time;
	socket my $fh, Socket::AF_INET, Socket::SOCK_STREAM, Socket::IPPROTO_TCP or die "$!";
	fh_nonblocking $fh, 1;
	
	connect $fh, Socket::sockaddr_in( $port, $addr )
		and do { fh_nonblocking $fh, 0; return $fh };
	
	warn "connect: $!";
	fhwait $fh, w => $start + $timeout - time;
}


1;
