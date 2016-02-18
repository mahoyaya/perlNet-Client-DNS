#!/usr/bin/env perl

use strict;
use warnings;
use IO::Pipe;
use IO::Select;


my @pipes;
my @pids;

my $s = IO::Select->new;

for (1..4) {
    push @pipes, my $p = IO::Pipe->new;
    my $pid = fork;
    if( $pid ) {
	#isParent
	warn 'fork ' . $pid;
	$p->reader;
	$p->blocking(0);
	$s->add($p);
	next;
    } else {
	#isChild
	$p->writer;
	sleep int(rand(5)) + 2;
	print $p $$ . " exit";
	warn "child exit";
	$p->close();
	exit 0;
    }
}

while(my @ready = $s->can_read() ) {
    warn "can_ready";
    for(@ready){
	warn 'for loop';
	my $str = '';
	while(read($_, my $buff, 1)){
	    $str .= $buff;
	}
	warn $str if length($str) > 0;
	$s->remove($_);
	$_->close();
    }
    sleep 1;
}

warn "parent exit";

exit 0;
