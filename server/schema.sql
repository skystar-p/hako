drop table if exists files cascade;

create table files (
    id bigserial primary key,
    content bytea,
    filename bytea,
    salt bytea check (length(salt) = 32),
    nonce bytea check (length(nonce) = 24)
);
