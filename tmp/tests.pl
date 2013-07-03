#!/usr/bin/env perl


package main;

use uni::perl ':dumper';
use lib::abs '../..';
use IO::Sync::Socket4;
use IO::Sync::RW;


=for rem
say my $fh = IO::Sync::Socket4->new->rawconnect( "74.125.232.1", 80 )
	|| die "$!";
IO::Sync::Socket4::fhwrite($fh, "GET / HTTP/1.0\n\n");
say IO::Sync::Socket4::fhread($fh, 4096, 1);
say "$!";
=cut

=for rem

say my $fh = IO::Sync::Socket4::tcp_connect( "google.com", 80 )
	|| die "$!";
IO::Sync::Socket4::fhwrite($fh, "GET / HTTP/1.0\n\n");
say IO::Sync::Socket4::fhread($fh, 4096, 1);
say "$!";

=cut

use Devel::Hexdump 'xd';
use uni::perl ':dumper';
use DR::Tarantool ();
use Time::HiRes 'time';

my $fh = IO::Sync::Socket4::tcp_connect( localhost => 33013 ) or die "$!";

my $seq = 0;

my $h = IO::Sync::RW->new(fh => $fh, timeout => 1);


my $start = time;

$h->writenb( pack( 'VVV', 0xff00, 0, ++$seq ) );
$h->writenb( pack( 'VVV', 0xff00, 0, ++$seq ) );
$h->writenb( pack( 'VVV', 0xff00, 0, ++$seq ) );


while () {

	$h->writenb( pack( 'VVV', 0xff00, 0, ++$seq ) );

	my $rbuf = $h->read( peekchunk => 8 ) or die;
	my ($type,$size) = unpack 'VV',$$rbuf;
	#say "type: $type, size: $size";
	$rbuf = $h->read( chunk => 12 + $size ) or next;
	#say xd $$rbuf;
	#say "DR: ".dumper DR::Tarantool::_pkt_parse_response($$rbuf);
	if (! ($seq % 1000)) {
		printf "%d, %0.2f/s\n", $seq, $seq/(time - $start);
	}

}

=for rem
while () {
	if( IO::Sync::Socket4::fhwrite($fh, pack( 'VVV', 0xff00, 0, ++$seq ) ) ) {
		say "ok";
		

		
		
		if ( IO::Sync::Socket4::fhwait($fh, r => 0.1) ) {
			if( my $ref = IO::Sync::Socket4::fhread( $fh, , 0 ) ) {
				my ($type,$size) = unpack 'VV',$$ref;
				$ref = IO::Sync::Socket4::fhread( $fh, 8, 0 )
			}
		}
	}
	last;
}
=cut


__END__
=cut

say dumper + IO::Sync::Socket4->new->resolve( A => "google.com" );





__END__
my $fh = IO::Sync::Socket4->new->connect( "74.125.232.1", 80 );

print { $fh } "GET / HTTP/1.0\n\n";
while (<$fh>) {
	print;
}

__END__

use Carp ();
use Socket qw(AF_INET SOCK_DGRAM SOCK_STREAM);

use AnyEvent::DNS;
use uni::perl ':dumper';
use Devel::Hexdump 'xd';
use Socket;

our @DNS_FALLBACK; # some public dns servers as fallback

{
   my $prep = sub {
      $_ = $_->[rand @$_] for @_;
      push @_, splice @_, rand $_, 1 for reverse 1..@_; # shuffle
      $_ = pack "H*", $_ for @_;
      \@_
   };

   my $ipv4 = $prep->(
      ["08080808", "08080404"], # 8.8.8.8, 8.8.4.4 - google public dns
#      ["d1f40003", "d1f30004"], # v209.244.0.3/4 - resolver1/2.level3.net - status unknown
      ["04020201", "04020203", "04020204", "04020205", "04020206"], # v4.2.2.1/3/4/5/6 - vnsc-pri.sys.gtei.net - effectively public
      ["cdd22ad2", "4044c8c8"], # 205.210.42.205, 64.68.200.200 - cache1/2.dnsresolvers.com - verified public
#      ["8d010101"], # 141.1.1.1 - cable&wireless - status unknown
   );

   @DNS_FALLBACK = (@$ipv4);
}

sub MAX_PKT() { 4096 } # max packet size we advertise and accept
sub DOMAIN_PORT() { 53 } # if this changes drop me a note
sub F_SETFL(){4}
sub O_NONBLOCK(){2048}


my $pkt = AnyEvent::DNS::dns_pack {
	rd => 1,
	id => 123,
	qd => [['google.com', 'A', 'in']],
};

sub mywait($$$) {
	my ($fh,$type,$timeout) = @_;
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




sub fhnb($$) {
	fcntl $_[0], F_SETFL, $_[1] ? O_NONBLOCK : 0 or die "$!";
}

socket my $fh, AF_INET, SOCK_STREAM, getprotobyname("tcp") or die "$!";
fhnb $fh, 1;
#my $sa = sockaddr_in( DOMAIN_PORT,inet_aton($DNS_FALLBACK[0]) );
my $sa = sockaddr_in( DOMAIN_PORT,$DNS_FALLBACK[0] );

my $timeout = 1;

if (connect $fh, $sa) {
	warn "connected";
}
else {
	warn "connect: $!";
	mywait $fh, w => $timeout;
	if (my $sin = getpeername $fh) {
		my ($port, $host) = unpack_sockaddr_in $sin;
		$host = inet_ntoa $host;
		warn "ok $host:$port";
	}
	elsif ($! == Errno::ENOTCONN) {
		sysread $fh, my $buf, 1;
		#warn "getpeername nc: $!";
		die "real error: $!";
	}
	else {
		warn "getpeername: $!";
		die "$!"
	}
}

send $fh, pack ( 'n/a*', $pkt ), 0 or die "$!";
mywait $fh, r => $timeout;
my $rc = recv $fh, my $msg, 4096, 0;# or die "recv: $!";
warn "recv = $rc";

say xd $msg;




#say xd $pkt;

#   push @{ $self->{queue} }, [dns_pack $req, $cb];


__END__

sub resolve($%) {
   my $cb = pop;
   my ($self, $qname, $qtype, %opt) = @_;

   $self->wait_for_slot (sub {
      my $self = shift;

      my @search = $qname =~ s/\.$//
         ? ""
         : $opt{search}
           ? @{ $opt{search} }
           : ($qname =~ y/.//) >= $self->{ndots}
             ? ("", @{ $self->{search} })
             : (@{ $self->{search} }, "");

      my $class = $opt{class} || "in";

      my %atype = $opt{accept}
         ? map +($_ => 1), @{ $opt{accept} }
         : ($qtype => 1);

      # advance in searchlist
      my ($do_search, $do_req);
      
      $do_search = sub {
         @search
            or (undef $do_search), (undef $do_req), return $cb->();

         (my $name = lc "$qname." . shift @search) =~ s/\.$//;
         my $depth = 10;

         # advance in cname-chain
         $do_req = sub {
            $self->request ({
               rd => 1,
               qd => [[$name, $qtype, $class]],
            }, sub {
               my ($res) = @_
                  or return $do_search->();

               my $cname;

               while () {
                  # results found?
                  my @rr = grep $name eq lc $_->[0] && ($atype{"*"} || $atype{$_->[1]}), @{ $res->{an} };

                  (undef $do_search), (undef $do_req), return $cb->(@rr)
                     if @rr;

                  # see if there is a cname we can follow
                  my @rr = grep $name eq lc $_->[0] && $_->[1] eq "cname", @{ $res->{an} };

                  if (@rr) {
                     $depth--
                        or return $do_search->(); # cname chain too long

                     $cname = 1;
                     $name = lc $rr[0][4];

                  } elsif ($cname) {
                     # follow the cname
                     return $do_req->();

                  } else {
                     # no, not found anything
                     return $do_search->();
                  }
                }
            });
         };

         $do_req->();
      };

      $do_search->();
   });
}


sub resolve_draft {
	my $self = shift;
	my ($type,$name,$host) = @_;
	my $timeout = 5;
	
	my $adns = bless {}, 'AnyEvent::DNS';
	$adns->os_config;
	my $servers = $adns->{server};
	#my $search = $adns->{search};
	warn dumper $servers;
	my $id = int rand 0xffff;
	my $pkt = AnyEvent::DNS::dns_pack {
		rd => 1,
		id => $id,
		qd => [[ $host, $name, $type ]],
	};
	
	say xd $pkt;
	socket my $fh4, Socket::AF_INET , Socket::SOCK_DGRAM(), 0 or die "$!";
	
	#for my $server (@$servers, @AnyEvent::DNS::DNS_FALLBACK) {
	for my $server (@AnyEvent::DNS::DNS_FALLBACK) {
		warn sprintf "Sending UDP to %s:dns...\n", AnyEvent::Socket::format_ipv4($server);
		my $sa = AnyEvent::Socket::pack_sockaddr (DOMAIN_PORT, $server);
		send $fh4, $pkt, 0, $sa;
		
		recv $fh4, my $buf, MAX_PKT, 0;
		say xd $buf;
		last;
		
		my $pk2 = fhrecv( $fh4, MAX_PKT, 0, 5 )
			or warn "recv: $!";
		say "recv: ".xd $pk2;
		if ($pk2) {
			return;
		}
=for rem
		warn sprintf "connecting to %s:dns...\n", AnyEvent::Socket::format_ipv4($srv);
		if( my $fh = $self->connect( $srv, 53 ) ) {
			
			fhwrite( $fh, pack ( 'n/a*', $pkt ), 1 ) or die "send failed: $!";
			my $pk1 = fhread( $fh, MAX_PKT, 5 )
				or warn "read: $!";
			say "read: ".xd $pk1;
			my $pk2 = fhrecv( $fh4, MAX_PKT, 0, 5 )
				or warn "recv: $!";
			say "recv: ".xd $pk2;
			
			#send $fh, pack ( 'n/a*', $pkt ), 0 or die "$!";
			#mywait $fh, r => $timeout;
			#my $rc = recv $fh, my $msg, 4096, 0;# or die "recv: $!";
			#warn "recv = $rc";
			
			return;
		}
=cut
	}
	return;
}


}
