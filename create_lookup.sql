CREATE TABLE location(
   id serial PRIMARY KEY,
   name VARCHAR (255) NOT NULL,
   current_id_sequence INT NOT NULL
);

INSERT INTO location(name, current_id_sequence) VALUES ('DC0001', 1000001);
INSERT INTO location(name, current_id_sequence) VALUES ('DC0002', 2000001);
INSERT INTO location(name, current_id_sequence) VALUES ('DC0003', 3000001);
INSERT INTO location(name, current_id_sequence) VALUES ('DC0004', 4000001);