drop table if exists files cascade;
create table files (
    id bigserial primary key,
    created_at timestamp with time zone default now(),
    filename bytea not null,
    salt bytea not null check (length(salt) = 32),
    stream_nonce bytea not null check (length(stream_nonce) = 19),
    filename_nonce bytea not null check (length(filename_nonce) = 24),
    upload_complete boolean not null default false
);

drop table if exists file_contents cascade;
create table file_contents (
    id bigserial primary key,
    created_at timestamp with time zone default now(),
    file_id bigint not null references files(id) on delete cascade,
    seq bigint not null,
    content bytea not null,

    unique (file_id, seq)
);
