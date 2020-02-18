DO
$$
DECLARE
    sequence character varying(255);
    row record;
BEGIN
    SELECT current_id_sequence INTO sequence FROM location WHERE name = 'DC0001';
    FOR row IN SELECT relname FROM pg_class WHERE relkind = 'S'
    LOOP
        EXECUTE 'ALTER SEQUENCE ' || row.relname || ' RESTART ' || sequence || ';';
    END LOOP;
END;
$$;