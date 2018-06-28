INSERT INTO users(email,password,certificate,active)VALUES('pera@exapmle.com','$2a$04$TaXiwfU9PIZDVRCZ7ffq0eEY2rmBy0z2zamyCmptL26SajV05s9Z.',NULL,true)
INSERT INTO users(email,password,certificate,active)VALUES('zika@example.com','$2a$04$PlFq74Hb9u20gbLpkrmRIOOjcqF1Hp0BQgG4/3T0yuIMjY.NX8bhK',NULL,true)

INSERT INTO authority(name)VALUES('ADMIN')
INSERT INTO authority(name)VALUES('REGULAR')

INSERT INTO user_authority(user_id,authority_id)VALUES(1,1)
INSERT INTO user_authority(user_id,authority_id)VALUES(2,2)

