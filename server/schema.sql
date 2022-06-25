create table if not exists files (
    id integer primary key,
    created_at timestamp with time zone default current_timestamp,
    filename blob not null,
    salt blob not null check (length(salt) = 32),
    nonce blob not null,
    filename_nonce blob not null,
    is_text boolean not null default false,
    available boolean not null default false
);

create table if not exists file_contents (
    id integer primary key,
    created_at timestamp with time zone default current_timestamp,
    file_id integer not null,
    seq integer not null,
    content blob not null,

    foreign key (file_id) references files(id) on delete cascade,
    unique (file_id, seq)
);
