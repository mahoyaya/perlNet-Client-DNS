use v5.12.0;
use strict;
use warnings;

my @hosts = qw(www.google.com www.yahoo.co.jp);

for(@hosts){
    chomp();
    my @d;
    my @strings = split /\./, $_;
    push(@d, length($_)) for @strings;;
    say join(",", @strings);
    say join(",", @d);
    for(my $i = 0; $i < scalar @d; $i++) {
	print unpack("H*", pack("C", $d[$i]));
	print ",";
	print unpack("H*", $strings[$i]);
	print ",";
    }
    say "";
}

__END__
