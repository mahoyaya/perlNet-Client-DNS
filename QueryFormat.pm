package QueryFormat;
use Class::Struct;

struct QueryFormat => {
    ID                 => '$', # 16bit, transaction id
    QR               => '$', # 1bit, query 0, reply 1
    OPCODE      => '$', # 4bit, standard 0, inverse 1, server status request 2
    AA               => '$', # 1bit, Authorative Answer
    TC                => '$', # 1bit, TurnCation, is fragment 1
    RD               => '$', # 1bit, Recursion Desired, request Recursion 1
    RA               => '$', # 1bit, Recursion Available, support Recursion 1
    PRT1            => '$', # 3bit, reserved bits, 000
    RCODE        => '$', # 4bit, no error 0, format error 1, server error 2, name error 3, undef 4, refuse 5
    QUESTION   => '$', # 16bit, question
    ANSWER     => '$', # 16bit, answer
    AUTHORITY  => '$', # 16bit, authority
    ADDITIONAL => '$', # 16bit, additional
    QRS => '@',
    ANSS => '@',
    AUTHS => '@',
    ADDS => '@',
};

struct QuestionResult => {
    NAME => '$',
    TYPE => '$',
    CLASS => '$',
};

struct AnswerResult => {
    NAME => '$',
    TYPE => '$',
    CLASS => '$',
    TTL => '$',
    LENGTH => '$',
    DATA => '$',
};

struct AAnswerResult => {
    NAME => '$',
    TYPE => '$',
    CLASS => '$',
    TTL => '$',
    LENGTH => '$',
    DATA => '$',
};

struct PTRAnswerResult => {
    NAME => '$',
    TYPE => '$',
    CLASS => '$',
    TTL => '$',
    DATA => '$',
};

struct MXAnswerResult => {
    NAME => '$',
    TYPE => '$',
    CLASS => '$',
    TTL => '$',
    LENGTH => '$',
    PREFERENCE => '$',
    DATA => '$',
};

struct NSAnswerResult => {
    NAME => '$',
    TYPE => '$',
    CLASS => '$',
    TTL => '$',
    DATALENGTH => '$',
    DATA => '$',
};

struct CNAMEAnswerResult => {
    NAME => '$',
    TYPE => '$',
    CLASS => '$',
    TTL => '$',
    DATALENGTH => '$',
    DATA => '$',
};

struct ROAAnswerResult => {
    NAME => '$',
    TYPE => '$',
    CLASS => '$',
    TTL => '$',
    DATALENGTH => '$',
    DATA => '$',
};


1;
