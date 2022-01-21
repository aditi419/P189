import hashlib 
import ctypes
from tkinter import *
from firebase import firebase

registration_window = Tk()
registration_window.geometry("400x400")
registration_window.configure(background='orange')

firebase = firebase.FirebaseApplication('https://p188-be57c-default-rtdb.firebaseio.com/', None)
login_username_entry = ''
login_password_entry = ''

def login(): 
    print("login function")
    global login_username_entry
    global login_password_entry
    username = login_username_entry.get()
    password = login_password_entry.get()
    encrypted_password = hashliv.md5(password.encode())
    hexadecimal_password = encrypted_password.hexdigest()
    print(hexadecimal_password)
    get_password = firebase.get('/', username)
    if(get_password != None):
        Mbox(title='Great Job!',message='Successfully logged in')
    elif(get_password == None):
        Mbox(title='Try Again!',message='Please check your password')
    else:
        Mbox(title='User not registered!',message='Get yourself registered first to login')
def register(): 
    print("register function")
    username = login_username_entry.get()
    password = login_password_entry.get()
    encrypt_pass = password.encode()
    pass_hash = hashlib.md5(encrypt_pass)
    pass_hex = encrypt_pass.hexdigest()
    print(pass_hex)
    firebase.put('/',username,pass_hex)
    
def login_window():
    login_window = Tk()
    login_window.geometry("400x400")
    login_window.configure(background='orange')
    
    global login_username_entry
    global login_password_entry
    registration_window.destroy()
    
    
    log_heading_label = Label(login_window, text="Log In" , font = 'arial 18 bold',bg='orange')
    log_heading_label.place(relx=0.5,rely=0.2, anchor=CENTER)
    
    login_username_label = Label(login_window, text="Username : " , font = 'arial 13',bg='orange')
    login_username_label.place(relx=0.3,rely=0.4, anchor=CENTER)
    
    login_username_entry = Entry(login_window)
    login_username_entry.place(relx=0.6,rely=0.4, anchor=CENTER)
    
    login_password_label = Label(login_window, text="Password : " , font = 'arial 13',bg='orange')
    login_password_label.place(relx=0.3,rely=0.5, anchor=CENTER)
    
    login_password_entry = Entry(login_window)
    login_password_entry.place(relx=0.6,rely=0.5, anchor=CENTER)
    
    btn_login = Button(login_window, text="Log In" , font = 'arial 13 bold' , command=login, relief=FLAT,bg='black',fg='black')
    btn_login.place(relx=0.5,rely=0.65, anchor=CENTER)
    
    login_window.mainloop()
    
    
heading_label = Label(registration_window, text="Register" , font = 'arial 18 bold',bg='orange')
heading_label.place(relx=0.5,rely=0.2, anchor=CENTER)

username_label = Label(registration_window, text="Username : " , font = 'arial 13',bg='orange')
username_label.place(relx=0.3,rely=0.4, anchor=CENTER)

username_entry = Entry(registration_window)
username_entry.place(relx=0.6,rely=0.4, anchor=CENTER)

password_label = Label(registration_window, text="Password :  " , font = 'arial 13',bg='orange')
password_label.place(relx=0.3,rely=0.5, anchor=CENTER)

password_entry = Entry(registration_window)
password_entry.place(relx=0.6,rely=0.5, anchor=CENTER)

btn_reg = Button(registration_window, text="Sign Up" , font = 'arial 13 bold' ,command=register, relief=FLAT, padx=10,bg='black',fg='black')
btn_reg.place(relx=0.5,rely=0.75, anchor=CENTER)

btn_login_window = Button(registration_window, text="Log In" , font = 'arial 10 bold' ,  command=login_window, relief=FLAT,bg='black',fg='black')
btn_login_window.place(relx=0.9,rely=0.06, anchor=CENTER)
registration_window.mainloop()