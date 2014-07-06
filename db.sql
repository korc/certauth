CREATE TABLE requests (
  req_id text not null primary key,
  spkac text not null,
  uname text not null,
  resource text not null,
  request_info text,
  cert_serial integer references certs(cert_serial)
);

CREATE TABLE users (
  uname text not null primary key
);

CREATE TABLE certs (
  cert_serial integer primary key,
  cert text
);

CREATE TABLE user_certs (
  uname text references users(uname),
  resource text not null,
  cert_serial integer not null references certs(cert_serial),
  UNIQUE (uname, resource, cert_serial)
);
