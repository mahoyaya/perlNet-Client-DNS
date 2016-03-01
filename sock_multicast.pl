#!/usr/bin/env perl
use strict;
use warnings;

use IO::Select;
use IO::Socket::INET;
use Socket qw(SOL_SOCKET SO_RCVBUF IPPROTO_IP IP_TTL INADDR_ANY IP_ADD_SOURCE_MEMBERSHIP IP_ADD_MEMBERSHIP IP_DROP_MEMBERSHIP IP_MULTICAST_LOOP IP_MULTICAST_IF IP_MULTICAST_TTL pack_ip_mreq pack_ip_mreq_source);
#use Socket qw(SOL_SOCKET SO_RCVBUF IPPROTO_IP IP_TTL INADDR_ANY IP_ADD_SOURCE_MEMBERSHIP IP_DROP_SOURCE_MEMBERSHIP IP_MULTICAST_LOOP IP_MULTICAST_IF IP_MULTICAST_TTL pack_ip_mreq_source);


#my $sock = IO::Socket::INET->new(PeerAddr => '224.0.0.251', PeerPort => 5353, LocalPort => 5353, Proto => 'udp') or die "Cannot create socket: $@";
#$sock->setsockopt(SOL_SOCKET, SO_REUSEADDR, 1) or die "setsockopt: $!";
#$sock->setsockopt(SOL_SOCKET, SO_RCVBUF, 64*1024) or die "setsockopt: $!";

my $sock;
socket($sock, AF_INET, SOCK_DGRAM, 0) || die "Cannot open socket: $!";


my $multiaddr = inet_aton("224.0.0.251");
#my $source = inet_aton("0.0.0.0");
my $source = inet_aton("192.168.0.14");
my $interface = INADDR_ANY;
#my $interface = inet_aton("192.168.0.14");
my $ip_mreq_source = pack_ip_mreq_source $multiaddr, $source, $interface;
my $ip_mreq = pack_ip_mreq($multiaddr, $interface);
#my $ip_mreq = pack_ip_mreq($multiaddr, $source);

my $multi_sock_addr = sockaddr_in(5353, $multiaddr);
my $bind_sock_addr = sockaddr_in(5353, $interface);
bind($sock, $bind_sock_addr);


setsockopt($sock, SOL_SOCKET, SO_REUSEADDR, 1) or die "setsockopt: $!"; # reuse timewait session
setsockopt($sock, SOL_SOCKET, SO_REUSEPORT, 1) or die "setsockopt: $!"; # reuse timewait session at same port number
setsockopt($sock, SOL_SOCKET, SO_RCVBUF, 64*1024) or die "setsockopt: $!";
setsockopt($sock, IPPROTO_IP, IP_MULTICAST_LOOP, 1) or die "setsockopt: $!"; # resent send packet to loopback interface. default 0, disable
setsockopt($sock, IPPROTO_IP, IP_MULTICAST_IF, $source) or die "setsockopt: $!"; # set interface(ip address)


print "join multicast group\n";

# マルチキャストグループに加入
#$sock->setsockopt(IPPROTO_IP, #multicast join group
#    IP_ADD_SOURCE_MEMBERSHIP,
#    $ip_mreq_source) or die "setsockopt: $!";
#$sock->setsockopt(IPPROTO_IP, #multicast join group
#                  IP_ADD_MEMBERSHIP,
#                  $ip_mreq) or die "setsockopt: $!"
setsockopt($sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, $ip_mreq) or die "setsockopt: $!"; # join the multicast group
#setsockopt($sock, IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, $ip_mreq_source) or die "setsockopt: $!"; # join the multicast group
setsockopt($sock, IPPROTO_IP, IP_MULTICAST_TTL, 1) or die "setsockopt: $!"; # set multicast ttl. default 1

#$sock->setsockopt(IPPROTO_IP, #multicast loop on/off
#                  IP_MULTICAST_LOOP,
#                  1) or die "setsockopt: $!";

#$sock->setsockopt(IPPROTO_IP, #multicast set multicast interface
#                  IP_MULTICAST_IF,
#                  $interface) or die "setsockopt: $!";

#print "so_rcvbuf length:" . length(getsockopt($sock, SOL_SOCKET, SO_RCVBUF)) . "\n";
#print "Receive buffer is ", $sock->getsockopt(SOL_SOCKET, SO_RCVBUF), " bytes\n";
print "Receive buffer is ", unpack("I", getsockopt($sock, SOL_SOCKET, SO_RCVBUF)), " bytes\n";

#print "IP TTL is ", $sock->getsockopt(IPPROTO_IP, IP_TTL), "\n";
print "IP TTL is ", unpack("I", getsockopt($sock, IPPROTO_IP, IP_TTL)), "\n";

print "IP Multicast TTL is ", unpack("I", getsockopt($sock, IPPROTO_IP, IP_MULTICAST_TTL)), "\n";


my $data = "0";
warn "request sending...";
send($sock, $data, 0, $multi_sock_addr) || die "send failed $!";

my $self = Properties->new;

my $rin = '';
vec($rin, fileno($sock), 1) = 1;
while(1) {
    warn "waiting data...";
    # データを待つ
    my ($nfound, $timeleft) = select(my $rout=$rin,undef,undef,$self->{TIMEOUT});
    #my $nfound = 1;

    if ($nfound) {
        my $max = 512;
        $max = 1410 if $self->{EDNS} > 0; # EDNSの推奨値1280-1410Bytes
        recv($sock, my  $rbuff, $max, 0) || die("recv failed $!");
        #alarm 0;
        warn(length($rbuff) . " Byte(s) data received.");
        my @ary = $rbuff =~ m/(.{1})/sg;
        dumpArray(\@ary);

    } else {
        warn "timeout.";
    }
    sleep 1;
}
#sleep 300;

print "exit multicast group\n";

# マルチキャストグループから削除
#$sock->setsockopt(IPPROTO_IP, #multicast join group
#    IP_DROP_SOURCE_MEMBERSHIP,
#    $ip_mreq_source) or die "setsockopt: $!";
#$sock->setsockopt(IPPROTO_IP, #multicast join group
#    IP_DROP_MEMBERSHIP,
#    $ip_mreq) or die "setsockopt: $!";
setsockopt($sock, IPPROTO_IP, IP_DROP_MEMBERSHIP, $ip_mreq) or die "setsockopt: $!";

exit;

sub dumpArray {
    # オクテットデータの配列を受け取り、文字か16進数で表示する
    #my $self = shift;
    my $aref = shift;
    my $prefix = shift;
    my $str = undef;
    for ( @$aref ) {
        my $b = unpack("C", $_);
        if ( $b > 47 && $b < 58 || $b > 64 && $b < 91 || $b > 96 && $b < 123 ) {
            #可読文字ならそのまま出力
            $str .= " " . $_;
        } else {
            #可読不可ならHEXに変換
            $str .= uc(unpack("H*", $_));
        }
        $str .= " ";
    }
    $prefix ? $str = $prefix . " " . $str : 1;
    warn "dumpArray:" .  $str;
    return;
}

#############################################################
package Properties;

sub new {
    my $class = shift;
    my $self = {
        TIMEOUT => 10,
        EDNS => 1,
    };
    bless $self, $class;
    return $self;
}


sub makeIGMPReport {
    my $self = shift;
    my $ver = "0001"; # 4bit, igmp version
    my $type = "0010"; # 4bit, igmp report/query 0001
    my $unused = "00000000"; # 8bit
    my $checksum = ""; # 16bit, checksum
    my $gaddress = inet_aton("224.0.0.251"); # 32bit, group address
}

1;
