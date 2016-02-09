PRAGMA foreign_keys=OFF;

BEGIN TRANSACTION;

CREATE TABLE hashes (
	id serial NOT NULL,
	hash VARCHAR(40) UNIQUE,
	complete INTEGER,
	downloaded INTEGER,
	incomplete INTEGER,
	done INTEGER,
	created TIMESTAMP,
	updated TIMESTAMP,
	PRIMARY KEY (id));


CREATE FUNCTION hash_created() RETURNS trigger AS $hash_created$
    BEGIN
    	NEW.created := current_timestamp;
    	NEW.updated := current_timestamp;
        RETURN NEW;
    END;
$hash_created$ LANGUAGE plpgsql;


CREATE FUNCTION hash_updated() RETURNS trigger AS $hash_updated$
    BEGIN
    	NEW.updated := current_timestamp;
        RETURN NEW;
    END;
$hash_updated$ LANGUAGE plpgsql;


CREATE TRIGGER insert_hashes_created BEFORE INSERT ON hashes FOR EACH ROW EXECUTE PROCEDURE hash_created();
CREATE TRIGGER insert_hashes_updated BEFORE UPDATE ON hashes FOR EACH ROW EXECUTE PROCEDURE hash_updated();


COMMIT;
