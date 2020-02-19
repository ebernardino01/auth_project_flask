DROP FUNCTION IF EXISTS public.f_update_sequence;
CREATE FUNCTION public.f_update_sequence(_location text)
  RETURNS void AS
$func$
DECLARE
    sequence character varying(255);
    row record;
BEGIN
    SELECT current_id_sequence INTO sequence FROM location WHERE name = _location;
    FOR row IN SELECT relname FROM pg_class WHERE relkind = 'S' and relname != 'location_id_seq'
    LOOP
        EXECUTE 'ALTER SEQUENCE ' || quote_ident(row.relname) || ' RESTART ' || sequence || ';';
    END LOOP;
END
$func$ LANGUAGE plpgsql;

SELECT public.f_update_sequence('DC0001');