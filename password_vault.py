# Import necessary libraries
import sqlite3
import hashlib
from tkinter import *
from tkinter import simpledialog
from functools import partial
import uuid
import pyperclip
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import random
import string
from tkinter import Canvas, Scrollbar, Frame

# Set up cryptography parameters
backend = default_backend()
salt = b'2444'

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=backend
)

encryptionKey = 0

# Define encryption and decryption functions
def encrypt(message: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(message)

def decrypt(message: bytes, token: bytes) -> bytes:
    return Fernet(token).decrypt(message)

# Database Code
with sqlite3.connect("password_Vault.db") as db:
    cursor = db.cursor()

# Create masterpassword and vault tables if they don't exist
cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL, 
recoveryKey TEXT NULL);
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS vault(
id INTEGER PRIMARY KEY,
website TEXT NOT NULL,
username TEXT NOT NULL, 
password TEXT NOT NULL);
""")

# Create Popup
def popUp(text):
    # Function to display a pop-up dialog and get user input
    answer = simpledialog.askstring("input string", text)
    return answer

# Window Interface
window = Tk()
window.update()
window.title("MaiVault")

# Make the window fullscreen
window.attributes('-fullscreen', True)

# Set background color
window.configure(bg='#F0F0F0') 

# Set the font for the Bauhaus 93
bauhaus_font = ("Bauhaus 93", 12)

def hashPassword(input):
    # Function to hash a password using SHA256
    hash1 = hashlib.sha256(input)
    hash1 = hash1.hexdigest()
    return hash1

# For New User
def newUserScreen():
    # Function to set up the interface for a new user
    cursor.execute('DELETE FROM vault')

    for widget in window.winfo_children():
        widget.destroy()

    title = Label(window, text="Welcome to MaiVault", bg="#FFFDD0", font=bauhaus_font)
    title.config(anchor=CENTER)
    title.pack()

    lbl = Label(window, text="Create Master Password", font=bauhaus_font)
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=10, show="*", font=bauhaus_font)
    txt.pack()
    txt.focus()

    lbl1 = Label(window, text="Re-enter Password", font=bauhaus_font)
    lbl1.config(anchor=CENTER)
    lbl1.pack()

    txt1 = Entry(window, width=10, show="*")
    txt1.pack()

    def savePassword():
        # Function to save the master password and recovery key
        if txt.get() == txt1.get():
            sql = "DELETE FROM masterpassword WHERE id = 1"
            cursor.execute(sql)

            hashedPassword = hashPassword(txt.get().encode('utf-8'))
            key = str(uuid.uuid4().hex)
            recoveryKey = hashPassword(key.encode('utf-8'))

            global encryptionKey
            encryptionKey = base64.urlsafe_b64encode(kdf.derive(txt.get().encode()))

            insert_password = """INSERT INTO masterpassword(password, recoveryKey)
            VALUES(?,?) """
            cursor.execute(insert_password, ((hashedPassword), (recoveryKey)))
            db.commit()

            recoveryScreen(key)
        else:
            lbl.config(text="Passwords do not match")

    btn = Button(window, text="Save", command=savePassword)
    btn.pack(pady=5)


def recoveryScreen(key):
    # Function to set up the recovery screen
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("350x150")
    lbl = Label(window, text="Save this key to recover this account!")
    lbl.config(anchor=CENTER)
    lbl.pack()

    lbl1 = Label(window, text=key)
    lbl1.config(anchor=CENTER)
    lbl1.pack()

    def copyKey():
        # Function to copy the recovery key to the clipboard
        pyperclip.copy(lbl1.cget("text"))

    btn = Button(window, text="Copy Key", command=copyKey)
    btn.pack(pady=5)

    def done():
        # Function to move to the password vault interface
        passwordVault()

    btn = Button(window, text="Done", command=done)
    btn.pack(pady=5)

def resetScreen():
    # Function to set up the screen for password reset
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("350x150")
    lbl = Label(window, text="Enter Recovery Key")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=10)
    txt.pack()
    txt.focus()

    lbl1 = Label(window)
    lbl1.config(anchor=CENTER)
    lbl1.pack()

    def getRecoveryKey():
        # Function to check the recovery key entered by the user
        recoveryKeyCheck = hashPassword(str(txt.get()).encode('utf-8'))
        cursor.execute('SELECT * FROM masterpassword WHERE id = 1 AND recoveryKey = ?', (recoveryKeyCheck,))
        return cursor.fetchall()

    def checkRecoveryKey():
        # Function to validate the recovery key and switch to new user screen
        checked = getRecoveryKey()
        if checked:
            newUserScreen()
        else:
            txt.delete(0, 'end')
            lbl1.config(text='Wrong Key')

    btn = Button(window, text="Check", command=checkRecoveryKey)
    btn.pack(pady=5)

# For Returning User
def loginScreen():
    # Function to set up the login screen
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("350x150")

    title = Label(window, text="Welcome to MaiVault")
    title.config(anchor=CENTER)
    title.pack()

    lbl = Label(window, text="Enter Master Password")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=10, show="*")
    txt.pack()
    txt.focus()

    lbl1 = Label(window)
    lbl1.config(anchor=CENTER)
    lbl1.pack(side=TOP)

    def getMasterPassword():
        # Function to check the entered master password
        checkHashedPassword = hashPassword(txt.get().encode('utf-8'))
        global encryptionKey
        encryptionKey = base64.urlsafe_b64encode(kdf.derive(txt.get().encode()))
        cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND password = ?", [(checkHashedPassword)])
        return cursor.fetchall()

    def checkPassword():
        # Function to validate the master password and switch to password vault
        password = getMasterPassword()

        if password:
            passwordVault()
        else:
            txt.delete(0, 'end')
            lbl1.config(text="Wrong Password")

    def resetPassword():
        resetScreen()

    btn = Button(window, text="Submit", command=checkPassword)
    btn.pack(pady=5)

    btn = Button(window, text="Reset Password", command=resetPassword)
    btn.pack(pady=5)

# After login, switch to the Password Management interface

def passwordVault():
    # Function to switch to the password vault interface
    # Destroy all existing widgets to prevent stacking
    for widget in window.winfo_children():
        widget.destroy()

    main_frame = Frame(window)
    main_frame.pack(fill=BOTH, expand=YES)

    canvas = Canvas(main_frame)
    canvas.pack(side=LEFT, fill=BOTH, expand=YES)

    scrollbar = Scrollbar(main_frame, orient=VERTICAL, command=canvas.yview)
    scrollbar.pack(side=RIGHT, fill=Y)

    canvas.configure(yscrollcommand=scrollbar.set)

    content_frame = Frame(canvas)
    canvas.create_window((0, 0), window=content_frame, anchor='nw')

    def on_canvas_configure(event):
        canvas.configure(scrollregion=canvas.bbox('all'))

    def on_mousewheel(event):
        canvas.yview_scroll(int(-1 * (event.delta / 120)), 'units')

    canvas.bind('<Configure>', on_canvas_configure)
    canvas.bind_all("<MouseWheel>", on_mousewheel)

    def addEntry():
        # Function to add a new entry to the password vault
        text1 = "Website"
        text2 = "Username"
        text3 = "Password"
        website = encrypt(popUp(text1).encode(), encryptionKey)
        username = encrypt(popUp(text2).encode(), encryptionKey)
        password = encrypt(popUp(text3).encode(), encryptionKey)

        insert_fields = """INSERT INTO vault(website,username,password)
        VALUES(?,?,?)"""
        cursor.execute(insert_fields, (website, username, password))
        db.commit()

        passwordVault()

    def removeEntry(input):
        # Function to remove an entry from the password vault
        cursor.execute("DELETE FROM vault WHERE id = ?", (input,))
        db.commit()
        passwordVault()

    def generateRandomPassword():
        # Function to generate a random password
        length = 12  # You can adjust the length of the generated password
        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(characters) for i in range(length))
        return password

    def showRandomPasswordPopup():
        # Function to display a popup with a randomly generated password
        random_password = generateRandomPassword()

        popup = Toplevel(window)
        popup.title("Generated Password")

        password_label = Label(popup, text=f"Generated Password:\n{random_password}")
        password_label.pack(pady=10)

        def copyPassword():
            # Function to copy the generated password to the clipboard
            pyperclip.copy(random_password)
            popup.destroy()

        copy_btn = Button(popup, text="Copy Password", command=copyPassword)
        copy_btn.pack(pady=10)
    
    lbl_maivault = Label(content_frame, text="MaiVault", font=("Bauhaus 93", 16))
    lbl_maivault.grid(row=0, column=1, pady=20)

    btn_generate_password = Button(content_frame, text="Generate Random Password", command=showRandomPasswordPopup)
    btn_generate_password.grid(column=0, row=1, pady=10)

    btn = Button(content_frame, text="+", command=addEntry)
    btn.grid(column=1, row=1, pady=10)  # Adjusted the row value to 1

    lbl = Label(content_frame, text="Website")
    lbl.grid(row=2, column=0, padx=80)
    lbl = Label(content_frame, text="Username")
    lbl.grid(row=2, column=1, padx=80)
    lbl = Label(content_frame, text="Password")
    lbl.grid(row=2, column=2, padx=80)

    cursor.execute("SELECT * FROM vault")
    if cursor.fetchall() is not None:
        i = 0
        while True:
            cursor.execute("SELECT * FROM vault")
            array = cursor.fetchall()

            if len(array) == 0:
                break

            lbl1 = Label(content_frame, text=(decrypt(array[i][1], encryptionKey)), font=("Helvetica", 12))
            lbl1.grid(column=0, row=i + 3)
            lbl1 = Label(content_frame, text=(decrypt(array[i][2], encryptionKey)), font=("Helvetica", 12))
            lbl1.grid(column=1, row=i + 3)
            lbl1 = Label(content_frame, text=(decrypt(array[i][3], encryptionKey)), font=("Helvetica", 12))
            lbl1.grid(column=2, row=i + 3)

            btn = Button(content_frame, text="Delete", command=partial(removeEntry, array[i][0]))
            btn.grid(column=3, row=i + 3, pady=10)

            i = i + 1

            cursor.execute("SELECT * FROM vault")
            if len(cursor.fetchall()) <= i:
                break

    def on_closing():
        # Function to handle window closing and commit changes to the database
        db.commit()
        window.destroy()

    window.protocol("WM_DELETE_WINDOW", on_closing)

    # Add an Exit button
    btn_exit = Button(window, text="Exit Application", command=on_closing)
    btn_exit.pack(pady=10)

# Initial setup
try:
    cursor.execute("SELECT * FROM masterpassword")
    if cursor.fetchall():
        loginScreen()
    else:
        newUserScreen()
    window.mainloop()
except Exception as e:
    print(f"An error occurred: {e}")
finally:
    db.close()
