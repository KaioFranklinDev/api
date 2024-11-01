const sqliteConnection = require('../database/sqlite')
const AppError = require('../utils/AppError')
const { hash, compare } = require("bcryptjs")

class UsersController {
    async create(request, response) {
        const { name, email, password } = request.body;
        const database = await sqliteConnection();

        const checkUsersExists = await database.get("SELECT * FROM users WHERE email = (?)", [email])
        if (checkUsersExists) {
            throw new AppError("Esse email já esta em uso!")
        }

        const hashedtPassword = await hash(password, 8)

        await database.run(
            "INSERT INTO users (name, email, password) VALUES (?,?,?)",
            [name, email, hashedtPassword]
        )

        return response.status(201).json()
    }

    async update(request, response) {
        const { name, email, password, old_password } = request.body;
        const { id } = request.params;
        const database = await sqliteConnection();

        const user = await database.get("SELECT * FROM users WHERE id = (?)", [id])
        if (!user) {
            throw new AppError("Usuario não encontrado")
        }

        const userWithUpdatedEmail = await database.get("SELECT * FROM users WHERE email = (?)", [email] );

        if(userWithUpdatedEmail && userWithUpdatedEmail.id != id){
            throw new AppError("Esse email já está em uso")
        }

        user.name = name ?? user.name ;
        user.email = email ?? user.email;

        if(password && !old_password){
            throw new AppError("voce tem que informar a senha antiga para definir a nova senha")
        }

        if(password && old_password){
            const checkOldPassword = await compare(old_password, user.password)
            if(!checkOldPassword){
                throw new AppError("Senha não confere!")
            }
            user.password = await hash(password, 8)
        }

        await database.run(`
            UPDATE users SET
            name = ?,
            email = ?,
            password = ?,
            updated_at = DATETIME('now')
            WHERE id = ?`,
            [user.name, user.email, user.password, id ]
        )

        return response.sendStatus(202).json()

    }
}


module.exports = UsersController;