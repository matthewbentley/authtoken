use time::{now, Tm, strptime, Duration};
use crypto::mac::{Mac, MacResult};
use crypto::hmac::Hmac;
use crypto::sha2::Sha512Trunc224;
use rustc_serialize::base64::{ToBase64, FromBase64, URL_SAFE, FromBase64Error};
use hyper::header::{Headers, Cookie, SetCookie};
use cookie::Cookie as CookiePair;
use std::str::{FromStr, from_utf8, Utf8Error};
use std::string::ToString;
use std::fmt::{self, Debug};


pub struct AuthToken {
    pub time: Tm,
    pub data: String,
    hmac: MacResult,
}

#[derive(Debug)]
pub enum TokenError {
    Base64(FromBase64Error),
    FirstDotNotFound,
    Utf8(Utf8Error),
    SecondDotNotFound,
}


impl Debug for AuthToken {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "AuthToken {{ time: {:?}, data: {}, hmac: {:?} }}",
               self.time, self.data, self.hmac.code().to_base64(URL_SAFE))
    }
}

impl ToString for AuthToken {
    fn to_string(&self) -> String {
        let text = format!("{}.{}", self.data, self.time.to_timespec().sec)
            .as_bytes()
            .to_base64(URL_SAFE);

        format!("{}.{}", text, self.hmac.code().to_base64(URL_SAFE))
    }
}

impl FromStr for AuthToken {
    type Err = TokenError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 2 {
            return Err(TokenError::FirstDotNotFound);
        }

        let hmacpart = try!(parts.get(1).unwrap().from_base64());
        let hmac = MacResult::new_from_owned(hmacpart);

        let user = try!(parts.get(0).unwrap().from_base64());
        let userparts: Vec<&str> = try!(from_utf8(&user)).split('.').collect();
        if userparts.len() != 2 {
            return Err(TokenError::SecondDotNotFound);
        }

        let data = userparts.get(0).unwrap();
        let t = strptime(userparts.get(1).unwrap(), "%s").unwrap().to_utc();

        Ok(AuthToken {
            time: t,
            data: data.to_string(),
            hmac: hmac,
        })
    }
}

impl AuthToken {
    pub fn new(hmac_secret: &str, data: &str) -> AuthToken {
        AuthToken::new_with_time(hmac_secret, data, now().to_utc())
    }

    pub fn new_with_time(hmac_secret: &str, data: &str, t: Tm) -> AuthToken {
        let mut hmac = Hmac::new(Sha512Trunc224::new(), hmac_secret.as_bytes());
        let text = format!("{}.{}", data, t.rfc3339());
        hmac.input(text.as_bytes());

        AuthToken {
            time: t,
            data: data.to_string(),
            hmac: hmac.result(),
        }

    }

    pub fn verify_token(good: &AuthToken, unknown: &AuthToken) -> bool {
        let mut is_good = true;

        is_good = is_good && (good.hmac == unknown.hmac);

        let timeout = Duration::minutes(5);

        is_good = is_good && (unknown.time >= (now().to_utc() - timeout));

        is_good
    }

}

impl From<FromBase64Error> for TokenError {
    fn from(e: FromBase64Error) -> TokenError {
        TokenError::Base64(e)
    }
}

impl From<Utf8Error> for TokenError {
    fn from(e: Utf8Error) -> TokenError {
        TokenError::Utf8(e)
    }
}

pub fn set_auth_cookie(hmac_secret: &str, data: &str, headers: &mut Headers) {
    let token = AuthToken::new(hmac_secret, data);
    let c_pair = CookiePair::new("auth_token".to_string(), token.to_string());

    match headers.get_mut::<SetCookie>() {
        Some(c) => {
            c.push(c_pair);
            return;
        },
        None => {}
    };
    headers.set::<SetCookie>(SetCookie(vec![c_pair]));
}

pub fn verify_auth_cookie(hmac_secret: &str, headers: &Headers) -> bool {
    let to_verify = match get_auth_token_from_headers(headers) {
        Some(v) => v,
        None => return false
    };
    let good = AuthToken::new_with_time(hmac_secret, &to_verify.data,
                                        to_verify.time);

    AuthToken::verify_token(&good, &to_verify)
}

pub fn get_auth_token_from_headers(headers: &Headers) -> Option<AuthToken> {
    let cookies = match headers.get::<Cookie>() {
        Some(c) => c,
        None => return None
    };

    let mut auth_string = "".to_string();

    for c in cookies.iter() {
        if c.name == "auth_token" {
            auth_string = c.value.clone();
            break;
        }
    }

    match AuthToken::from_str(&auth_string) {
        Ok(v) => Some(v),
        Err(_) => None
    }
}
