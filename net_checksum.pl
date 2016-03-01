use strict;
use warnings;
use Carp;
use v5.12.0;
use Time::HiRes qw(usleep);
#use Net_CHKSUM;

my $start = Time::HiRes::time();

my $icmpheader = {
    type => 8,
    code => 0,
    chksum => 0,
    id => 1,
    seq => 4,
    data => "a",
};

## cksum => 38650 は icmpheaderから得たチェックサム値なのでこちらのデータをもとに計算すると戻り値が0x0000になる
my $correct_icmpheader = {
    type => 8,
    code => 0,
    chksum => 38650,
    id => 1,
    seq => 4,
    data => "a",
};

my $n = 0x96fa;
say $n;
say unpack("B16", pack("n", $n));

#my $h = $icmpheader;
my $h = $correct_icmpheader;
my $pkt;
$pkt .= pack("C", $h->{type} );
$pkt .= pack("C", $h->{code});
$pkt .= pack("n", $h->{chksum});
$pkt .= pack("n", $h->{id});
$pkt .= pack("n", $h->{seq});
$pkt .= $h->{data};

say "start:" . unpack("H*", $pkt) . ":end";
say "length: " .  length($pkt);

my @d = unpack("n*", $pkt);
say join ",", map { unpack("H*", pack("n", $_)) } @d;

my $rtn;
#for(1..100000) {
$rtn = Net_CHKSUM::chksum($pkt, 1);
#}
say $rtn;
say unpack "H*", pack "n", $rtn;
say sprintf "%0.5f", Time::HiRes::time - $start;

exit;

package Net_CHKSUM;
our $VERSION = '0.00001';
use strict;
use Carp;

#################################################################
# 関数名     : cksum
# 引数       : 引数1 packed data, 引数2 debug option
# 戻り値     : 16bit整数値
# 作成日時   : 20160224
# 作成者     : mahoyaya
# 関数の説明 : packされたパケットデータからチェックサムを返す
# 更新履歴   : なし
#################################################################
sub chksum {
    my $p = shift;
    my $debug = shift;
    my $sum = 0;

    my $s = Time::HiRes::time() if $debug;

    # padding data 0x00 if $p length is odd
    $p .= pack(qq/C/, 0) if length($p) % 2 == 1;
    carp "length: " . length($p) if $debug;

    # データを16bit 毎に数値化して足す
    for my $n (unpack("n*", $p)) {
        $sum += $n;
    }

    if ($debug) {
        carp "sum decimal               : " . $sum;
        carp "sum binary                : " . unpack("B*", pack("N", $sum)); # 32bit バイナリ数値
        carp "sum >> 16                 : " . unpack("B*", pack("n", $sum >> 16)); # 上位16bitの値
        carp "sum & 0xffff              : " . unpack("B*", pack("n", $sum & 0xffff)); # 下位16bitの値 on 32bit data, 0xffff = 0x0000ffff
    }
    $sum = ($sum >> 16) + ($sum & 0xffff); # 1の補数和
    if ($debug) {
        carp "sum binary                : " . unpack("B*", pack("n", $sum));
    }
    $sum = ~(($sum >> 16) + ($sum & 0xffff)) & 0x0000ffff; # 補数を得るために反転させて上位16bitをリセットする
    #$sum = ~(($sum >> 16) + ($sum & 0xffff)); # 補数を得るために反転させる # ビット演算のほうが速い
    if ($debug) {
        carp "sum reverse binary        : " . unpack("B*", pack("n", $sum)); # reverse
        carp "sum reverse binary to hex : " . unpack("H*", pack("n", $sum)); # reverse
    }
    $s = sprintf "%0.5f", Time::HiRes::time - $s if $debug;
    return $sum, $s if $debug;
    return $sum;
    #return unpack("n", pack("n", $sum)); # ビット演算のほうが速い
}

1;

__END__


=head1 SCRIPT NAME

Net_CHKSUM.pm

=head1 DESCRIPTION

This script is used to generate packet header checksum

=head1 SYNOPSIS

use Net_CHKSUM;
$unpacked_16bit_checksum = Net_CHKSUM::chksum($packed_data);

=head1 METHOD

chksum

概要 generate checksum
引数 packed data
リターンバリュー 16bit unsighned integer
例 $unpacked_16bit_checksum = Net_CHKSUM::chksum($packed_data);

=head1 other
特別に注意して特徴を述べたほうがいい場合は、一つ他のモジュールと比較したの優位性を書く
人のモジュールのPODを読むときは、モジュールの使い方だけでなく、使い方をどのような英語で表現しているのか頭に焼き付ける

=cut

