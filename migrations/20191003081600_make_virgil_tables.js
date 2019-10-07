
exports.up = function(knex) {
    return knex.schema
    .createTable('users', tbl => {
        tbl.increments();
        tbl
            .string('username', 128)
            .notNullable()
            .unique();
        tbl.string('password', 300).notNullable();
        tbl.string('firstName', 255).notNullable();
        tbl.string('lastName', 255).notNullable();
        tbl.string('email', 255)
        tbl.string('record');
    })
};

exports.down = function(knex) {
  return knex.schema
    .dropTableIfExists('users')
};
