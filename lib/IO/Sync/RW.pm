package IO::Sync::RW;

use strict;
use uni::perl ':dumper';
use IO::Sync::Socket4;
BEGIN{ *fhnb = \&AnyEvent::Util::fh_nonblocking; }
BEGIN{ *fhwait = \&IO::Sync::Socket4::fhwait; }
use Time::HiRes 'time';
use Carp;

sub MAX_READ_SIZE () { 128 * 1024 }

sub new {
	my $pk = shift;
	my $self = bless {@_}, $pk;
	$self->{debug} //= 1;
	$self->{for} = " (".fileno($self->{fh}).") @{[ (caller)[1,2] ]}" if $self->{debug};
	if ($self->{debug}) {
		warn sprintf "%08x creating IS::RW for%s\n", int $self, $self->{for};
	}
	$self->init();
	$self;
}

sub upgrade {
	my $self = shift;
	my $class = shift;
	$class =~ s{^\+}{} or $class = "AnyEvent::RW::$class";
	croak "$class is not a subclass of ".ref($self) if !UNIVERSAL::isa($class,ref($self));
	bless $self,$class;
	$self->init(@_);
}

sub init {
	my $self = shift;
	
	#$self->{debug} //= 1;
	$self->{wsize} = 1;
	$self->{wlast} = $self->{wbuf} = { s => 0 };
	$self->{timeout} ||= 5;
	
	$self->{read_size} ||= 4096;
	$self->{max_read_size} = $self->{read_size}
		if $self->{read_size} > ($self->{max_read_size} || MAX_READ_SIZE);
	
	fhnb $self->{fh}, 1;
	
	$self->{rbuf} = '';
	
	binmode $self->{fh}, ':raw';
	return;
}

sub read : method {
	my $self = shift;
	unshift @_, 'regex' if UNIVERSAL::isa( $_[0], 'Regexp' );
	$self->{rq} and die "Unprocessed rq: @{$self->{rq}}";
	push $self->{rq} = [@_];
	if ( length $self->{rbuf} ) {
		eval {
			$self->_drain_r();
		1} or do {
			if (ref $@ eq 'SCALAR' and ${$@} eq 'ENOUGH') {
				return delete $self->{result};
			} else {
				die $@;
			}
		}
	}
	$self->_try_read;
}

sub _try_read {
	my $self = shift;
	no warnings 'unopened';
	my $till = time + $self->{timeout};
	my ($buf,$len);
	while() {
		#warn "try read";
		while ( $len = sysread $self->{fh}, $self->{rbuf}, $self->{read_size}, length $self->{rbuf} ) {
			#$lsr = $len;
			#warn "read $len ";
			if ($len == $self->{read_size} and $self->{read_size} < $self->{max_read_size}) {
				$self->{read_size} *= 2;
				$self->{read_size} = $self->{max_read_size} || MAX_READ_SIZE
					if $self->{read_size} > ($self->{max_read_size} || MAX_READ_SIZE);
			}
			#warn "call drain";
			eval {
				$self->_drain_r();
			1} or do {
				if (ref $@ eq 'SCALAR' and ${$@} eq 'ENOUGH') {
					return delete $self->{result};
				} else {
					die $@;
				}
			}
		}
		#warn "lsr = $len/$!";
		if (defined $len) {
			$self->{_eof} = 1;
			$! = Errno::EPIPE;
			return ;# what to return?
		} else {
			if ($! == Errno::EAGAIN or $! == Errno::EINTR ) { # or $! == WSAEWOULDBLOCK
				#warn "EAVAIL, waiting for ".($till - time);
				fhwait( $self->{fh}, r => $till - time ) and next;
				die "read failed: @{[ $! = Errno::ETIMEDOUT ]}" if time > $till;
			} else {
				die "read failed: $!";
			}
		}
	}

}

sub _drain_r {
	my $self = shift;
	#warn "got rbuf $self->{rbuf}";
	#return if $self->{_skip_drain_rbuf};
	#local $self->{_skip_drain_rbuf} = 1;
	my $i = delete $self->{rq};
	
		my $len = length $self->{rbuf};
		#if ($i = shift @{ $self->{rq} }) 
		LOOP: {
			#warn "drain [ @$i ]";
			given ($i->[0]) {
				when ('line') {
					#warn "parse as line";
					if ((my $idx = index( $self->{rbuf}, "\n" )) > -1) {
						my $s = substr($self->{rbuf},0,$idx+1,'');
						#warn dumper $s;
						my $nl = substr($s,-2,1) eq "\015" ? substr( $s,-2,2,'' ) : substr($s,-1,1,'');
						#warn "index match $idx ".dumper $nl;
						$self->{result} = [$s,$nl];
						die \("ENOUGH");
					} else {
						last LOOP;
					}
				}
				when ('regex') {
					#warn "parse as regex $i->[1] ";#.dumper( $self->{rbuf} );
					if ( $self->{rbuf} =~ $i->[1] ) {
						#warn "regex match $+[0] ";
						$self->{result} = \(substr($self->{rbuf},0,$+[0],''));
						die \("ENOUGH");
					} else {
						last LOOP;
					}
				}
				when ('chunk') {
					#warn "parse as chunk $i->[1]";
					if ( $i->[1] == $len ) {
						$self->{result} = \(delete $self->{rbuf});
						die \("ENOUGH");
					}
					elsif ( $i->[1] < $len ) {
						$self->{result} = \(substr($self->{rbuf},0,$i->[1],''));
						die \("ENOUGH");
					} else {
						last LOOP;
					}
				}
				when ('peekchunk') {
					#warn "parse as chunk $i->[1]";
					if ( $i->[1] == $len ) {
						$self->{result} = \($self->{rbuf});
						die \("ENOUGH");
					}
					elsif ( $i->[1] < $len ) {
						$self->{result} = \(substr($self->{rbuf},0,$i->[1]));
						die \("ENOUGH");
					} else {
						last LOOP;
					}
				}
				when ('all') {
					#warn "pass all (eof=$self->{_eof})";
					if ($len > 0) {
						$self->{result} = \(delete $self->{rbuf});
						die \("ENOUGH");
					} else {
						warn "no data for $_";
						last LOOP;
					}
				}
				default {
					die "Unknown : $_";
				}
				#$self->_error( Errno::EPIPE ) if $self->{_eof};
				#last LOOP;
			}
		}
	
	$self->{rq} = $i;
	#if ($i) {
	#	warn "need more data for [@{[ @$i ]}]. Have ".length($self->{rbuf});
	#	unshift @{ $self->{rq} },$i;
	#} else {
	#	#warn "no more readers";
	#	#delete $self->{rw};
	#}
	return;
}

sub writenb {
	my $self = shift;
	my $buf = shift;
	my $len = syswrite($self->{fh},$buf);
	if (!defined $len) {
		die "write failed: $!"
	}
	elsif ( length $buf > $len ) {
		die "Partial write ($len < ".length($buf).")";
	}
	else {
		#warn "written $len";
	}
	return 1;
}

sub write :method {
	my $self = shift;
	ref $_[0] and die "Writing refs not supported yet";
	$self->{wsize}++;
	$self->{seq}++;
	my $l = { w => $_[0], s => $self->{seq} };
	$self->{wlast}{next} = $l;
	$self->{wlast} = $l;
	#warn dumper $self->{wbuf};
	$self->_ww;
}

1;
