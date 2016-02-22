package ResultA;

sub new {
    my $class = shift;
    my $self = {
        NAME => undef,
        TYPE => undef,
        CLASS => undef,
        TTL => undef,
        LENGTH => undef,
        DATA => undef,
    };
    bless $self, $class;
    return $self;
}

1;
