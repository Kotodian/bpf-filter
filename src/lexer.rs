use logos::Logos;

#[derive(Logos, Debug, PartialEq)]
#[logos(skip r"[ \t\n\f]+")] // Ignore this regex pattern between tokens
pub enum Token {
    #[token("dst")]
    Dst,

    #[token("src")]
    Src,

    #[token("outer")]
    Outer,

    #[token("inner")]
    Inner,

    #[regex(r"link|ether|ppp|slip|fddi|tr|wlan")]
    Link,

    #[token("ip")]
    IP,

    #[token("ip6")]
    IP6,

    #[token("tcp")]
    TCP,

    #[token("udp")]
    UDP,

    #[token("icmp")]
    ICMP,

    #[token("sctp")]
    SCTP,

    #[token("host")]
    HOST,

    #[token("net")]
    NET,

    #[token("mask")]
    MASK,

    #[token("port")]
    PORT,

    #[token("portrange")]
    PORTRANGE,

    #[token("proto")]
    PROTO,

    #[token("l7proto")]
    L7PROTO,

    #[token("device")]
    DEVICE,

    #[token("interface")]
    INTERFACE,

    #[regex(r"direction|dir")]
    DIR,

    #[regex(r"AND|and|&&")]
    And,

    #[regex(r"OR|or|\|\|")]
    Or,

    #[regex(r"NOT|not|!", priority = 3)]
    Not,

    #[token("vlan")]
    VLAN,

    #[token("mpls")]
    MPLS,

    #[token("gtp")]
    GTP,

    #[token("local")]
    LOCAL,

    #[token("remote")]
    REMOTE,

    #[token(">")]
    GT,

    #[token("<")]
    LT,

    #[token(">=")]
    GEQ,

    #[token("<=")]
    LEQ,

    #[token("!=")]
    NEQ,

    #[token("==")]
    EQ,

    #[token("[")]
    LBRACKET,

    #[token("]")]
    RBRACKET,

    #[token("(")]
    LPAREN,

    #[token(")")]
    RPAREN,

    #[token("&")]
    AndBit,

    #[regex(r"([0-9A-Fa-f]{2}([:-])){5}[0-9A-Fa-f]{2}", |lex| lex.slice().to_string())]
    EID(String),

    #[regex(r"[0-9]+|(0X|0x])[0-9A-Fa-f]+", |lex| lex.slice().parse::<u32>().unwrap(), priority=3)]
    NUM(u32),

    #[regex(r"((([0-9]+|(0X|0x)[0-9A-Fa-f]+)\.([0-9]+|(0X|0x)[0-9A-Fa-f]+))|(([0-9]+|(0X|0x)[0-9A-Fa-f]+)\.([0-9]+|(0X|0x)[0-9A-Fa-f]+)\.([0-9]+|(0X|0x)[0-9A-Fa-f]+))|(([0-9]+|(0X|0x)[0-9A-Fa-f]+)\.([0-9]+|(0X|0x)[0-9A-Fa-f]+)\.([0-9]+|(0X|0x)[0-9A-Fa-f]+)\.([0-9]+|(0X|0x)[0-9A-Fa-f]+)))", |lex| lex.slice().to_string())]
    HID(String),

    #[regex(r"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))", |lex| lex.slice().to_string())]
    HID6(String),

    #[regex(r"[A-Za-z0-9_]+", |lex| lex.slice().to_string())]
    ID(String),

    #[regex(r"[0-9]*(-[0-9]*)?", |lex| lex.slice().to_string())]
    PID(String),

    #[regex(r#""([^"]*)""#, |lex| lex.slice()[1..lex.slice().len()-1].to_string())]
    #[regex(r#"'([^']*)'"#, |lex| lex.slice()[1..lex.slice().len()-1].to_string())]
    QUOTED(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tokenize() {
        let input = r#"ip and host "example.com" or port 80"#;
        let mut lexer = Token::lexer(input);

        assert_eq!(lexer.next().unwrap(), Ok(Token::IP));
        assert_eq!(lexer.next().unwrap(), Ok(Token::And));
        assert_eq!(lexer.next().unwrap(), Ok(Token::HOST));
        assert_eq!(
            lexer.next().unwrap(),
            Ok(Token::QUOTED("example.com".to_string()))
        );
        assert_eq!(lexer.next().unwrap(), Ok(Token::Or));
        assert_eq!(lexer.next().unwrap(), Ok(Token::PORT));
        assert_eq!(lexer.next().unwrap(), Ok(Token::NUM(80)));
        assert_eq!(lexer.next(), None);

        let input = "portrange 80-800";
        let mut lexer = Token::lexer(input);

        assert_eq!(lexer.next().unwrap(), Ok(Token::PORTRANGE));
        assert_eq!(lexer.next().unwrap(), Ok(Token::PID("80-800".to_string())));
    }
}
