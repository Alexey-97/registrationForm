import hashlib
import sqlite3
from tkinter import *
from tkinter import messagebox as mb

connect = sqlite3.connect("data.db")
cursor = connect.cursor()


# Создание таблицы
cursor.execute('''CREATE TABLE IF NOT EXISTS  users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    login VARCHAR (30) NOT NULL UNIQUE,
    password VARCHAR (64) NOT NULL
    )''')


def password_sha256(user_password):
    """Кодировка пароля"""
    salt = ("jddidouhs")
    password = bytes(user_password + salt, 'utf-8')
    password_hash = hashlib.sha256(password)
    return password_hash.hexdigest()


def register():
    """Регистрация пользователя"""
    login = entLogin.get().strip()
    password = password_sha256(ent_password.get())
    cursor.execute("INSERT INTO users (login, password) VALUES (?, ?)", [login, password])
    connect.commit()
    mb.showinfo("Регистрация", "Пользователь " + login + " успешно зарегистрирован!")


def auch_window():
    """Окно авторизации"""
    def user_auch():
        """Авторизация пользователя"""
        login = entLogin_auch.get().strip()
        password = password_sha256(ent_password_auch.get())
        cursor.execute("SELECT password FROM users WHERE login = ? AND password = ? LIMIT 1", [login, password])
        info = cursor.fetchall()
        if len(info) > 0:
            mb.showinfo("Авторизация", "Добро пожаловать!")
        else:
            mb.showerror("Авторизация ", "Неверный пароль!")

    auch = Toplevel()
    auch.geometry("300x300")
    auch.title("Авторизация")
    auch.resizable(0, 0)
    lb_Main = Label(auch, text="Авторизация", font="Calibri 22")
    lb_Main.place(x=20, y=30)

    lb_Login = Label(auch, text="Логин", font="Calibri 13")
    lb_Login.place(x=20, y=100)

    entLogin_auch = Entry(auch, width=15, font="Calibri 13")
    entLogin_auch.place(x=80, y=100)

    lb_password = Label(auch, text="Пароль", font="Calibri 13")
    lb_password.place(x=20, y=160)

    ent_password_auch = Entry(auch, width=15, font="Calibri 13")
    ent_password_auch.place(x=80, y=160)

    btn_auth = Button(auch, text="Войти", font=16, command=user_auch)
    btn_auth.place(x=20, y=250)


root = Tk()
root.geometry("300x300")
root.title("Регистрация")
root.resizable(0, 0)
lb_Main = Label(text="регистрация", font="Calibri 22")
lb_Main.place(x=20, y=30)

lb_Login = Label(text="Логин", font="Calibri 13")
lb_Login.place(x=20, y=100)

entLogin = Entry(width=15, font="Calibri 13")
entLogin.place(x=80, y=100)

lb_password = Label(text="Пароль", font="Calibri 13")
lb_password.place(x=20, y=160)

ent_password = Entry(width=15, font="Calibri 13")
ent_password.place(x=80, y=160)

btn_register = Button(text="Зарегистрироваться", font=16, command=register)
btn_register.place(x=20, y=200)

btn_Auth = Button(text="Войти", font=16, command=auch_window)
btn_Auth.place(x=20, y=250)

root.mainloop()
