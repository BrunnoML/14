import streamlit as st
import sqlite3
import pandas as pd
from PIL import Image
import bcrypt
import io
import base64
import os

# Função para criar a conexão com o banco de dados
def get_db_connection():
    conn = sqlite3.connect('database.db')
    return conn

# Função para inicializar o banco de dados
def initialize_db():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            foto BLOB,
            nome TEXT NOT NULL,
            vulgo TEXT NOT NULL,
            documento TEXT NOT NULL,
            obs TEXT
        )
    ''')
    conn.commit()
    conn.close()

# Função para verificar o login
def login_user(username, password):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT password FROM users WHERE username = ?', (username,))
    data = c.fetchone()
    conn.close()
    if data:
        hashed_password = data[0]
        return bcrypt.checkpw(password.encode(), hashed_password.encode())
    return False

# Função para registrar um novo usuário
def register_user(username, password):
    conn = get_db_connection()
    c = conn.cursor()
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
    conn.commit()
    conn.close()

# Função para adicionar um novo registro
def add_record(foto, nome, vulgo, documento, obs):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('INSERT INTO records (foto, nome, vulgo, documento, obs) VALUES (?, ?, ?, ?, ?)', (foto, nome, vulgo, documento, obs))
    conn.commit()
    conn.close()

# Função para atualizar um registro
def update_record(record_id, foto, nome, vulgo, documento, obs):
    conn = get_db_connection()
    c = conn.cursor()
    if foto is not None:
        c.execute('UPDATE records SET foto = ?, nome = ?, vulgo = ?, documento = ?, obs = ? WHERE id = ?', (foto, nome, vulgo, documento, obs, record_id))
    else:
        c.execute('UPDATE records SET nome = ?, vulgo = ?, documento = ?, obs = ? WHERE id = ?', (nome, vulgo, documento, obs, record_id))
    conn.commit()
    conn.close()

# Função para deletar um registro
def delete_record(record_id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('DELETE FROM records WHERE id = ?', (record_id,))
    conn.commit()
    conn.close()

# Função para buscar registros
def search_records(search_term):
    conn = get_db_connection()
    c = conn.cursor()
    query = '''
        SELECT id, foto, nome, vulgo, documento, obs FROM records 
        WHERE nome LIKE ? OR vulgo LIKE ? OR documento LIKE ? OR obs LIKE ?
    '''
    like_term = f'%{search_term}%'
    c.execute(query, (like_term, like_term, like_term, like_term))
    data = c.fetchall()
    conn.close()
    return data

# Função para listar todos os registros
def list_all_records():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT id, foto, nome, vulgo, documento, obs FROM records')
    data = c.fetchall()
    conn.close()
    return data

# Função para buscar registro por ID
def get_record_by_id(record_id):
    conn = get_db_connection()
    c = conn.cursor()
    query = 'SELECT id, foto, nome, vulgo, documento, obs FROM records WHERE id = ?'
    c.execute(query, (record_id,))
    data = c.fetchone()
    conn.close()
    return data

# Função para transformar bytes em imagem
def bytes_to_image(byte_data):
    return Image.open(io.BytesIO(byte_data))

# Função para transformar bytes em base64
def bytes_to_base64(byte_data):
    return base64.b64encode(byte_data).decode()

# Página de Login
def login_page():
    st.title("Login")
    username = st.text_input("Nome de usuário")
    password = st.text_input("Senha", type='password')
    if st.button("Entrar"):
        if login_user(username, password):
            st.session_state.logged_in = True
            st.session_state.username = username
            st.session_state.page = "Principal"
            st.experimental_rerun()
        else:
            st.error("Nome de usuário ou senha inválidos")

# Página de Registro
def register_page():
    st.title("Registrar")
    username = st.text_input("Nome de usuário")
    password = st.text_input("Senha", type='password')
    if st.button("Registrar"):
        register_user(username, password)
        st.success("Usuário registrado com sucesso")

# Página principal da aplicação
def main_page():
    st.title("Aplicação de Banco de Dados")
    st.sidebar.header(f"Logado como: {st.session_state.username}")
    
    menu = ["Adicionar Registro", "Listar Registros", "Buscar Registros"]
    choice = st.sidebar.selectbox("Menu", menu)
    
    if choice == "Adicionar Registro":
        st.subheader("Adicionar Registro")
        foto = st.file_uploader("Enviar Foto", type=["jpg", "jpeg", "png"])
        nome = st.text_input("Nome")
        vulgo = st.text_input("Vulgo")
        documento = st.text_input("Documento")
        obs = st.text_area("Observações")
        
        if st.button("Adicionar Registro"):
            if foto and nome and vulgo and documento:
                foto_bytes = foto.read()
                add_record(foto_bytes, nome, vulgo, documento, obs)
                st.success("Registro adicionado com sucesso")
            else:
                st.error("Por favor, preencha todos os campos")
    
    elif choice == "Listar Registros":
        st.subheader("Listar Registros")
        records = list_all_records()
        for record in records:
            st.write("---")
            st.image(bytes_to_image(record[1]), width=100)
            st.write(f"Nome: {record[2]}")
            st.write(f"Vulgo: {record[3]}")
            st.write(f"Documento: {record[4]}")
            st.write(f"Observações: {record[5]}")
            if st.button(f"Editar {record[0]}", key=f"edit_{record[0]}"):
                st.session_state.editing_record_id = record[0]
                st.session_state.page = "Editar Registro"
                st.experimental_rerun()
            if st.button(f"Excluir {record[0]}", key=f"delete_{record[0]}"):
                st.session_state.deleting_record_id = record[0]
                st.session_state.page = "Excluir Registro"
                st.experimental_rerun()

    elif choice == "Buscar Registros":
        st.subheader("Buscar Registros")
        search_term = st.text_input("Buscar")
        if st.button("Buscar"):
            results = search_records(search_term)
            for result in results:
                st.write("---")
                st.image(bytes_to_image(result[1]), width=100)
                st.write(f"Nome: {result[2]}")
                st.write(f"Vulgo: {result[3]}")
                st.write(f"Documento: {result[4]}")
                st.write(f"Observações: {result[5]}")
                if st.button(f"Editar {result[0]}", key=f"edit_{result[0]}"):
                    st.session_state.editing_record_id = result[0]
                    st.session_state.page = "Editar Registro"
                    st.experimental_rerun()
                if st.button(f"Excluir {result[0]}", key=f"delete_{result[0]}"):
                    st.session_state.deleting_record_id = result[0]
                    st.session_state.page = "Excluir Registro"
                    st.experimental_rerun()

# Página de edição de registro
def edit_record_page(record_id):
    st.title("Editar Registro")
    record = get_record_by_id(record_id)
    if record:
        foto = st.file_uploader("Foto", type=["jpg", "jpeg", "png"])
        nome = st.text_input("Nome", record[2])
        vulgo = st.text_input("Vulgo", record[3])
        documento = st.text_input("Documento", record[4])
        obs = st.text_area("Observações", record[5])
        
        if st.button("Atualizar Registro"):
            foto_bytes = foto.read() if foto else None
            update_record(record_id, foto_bytes, nome, vulgo, documento, obs)
            st.success("Registro atualizado com sucesso")
            st.session_state.page = "Principal"
            st.experimental_rerun()
        
        if st.button("Excluir Registro"):
            st.session_state.deleting_record_id = record_id
            st.session_state.page = "Excluir Registro"
            st.experimental_rerun()

# Página de exclusão de registro
def delete_record_page(record_id):
    st.title("Excluir Registro")
    st.warning("Tem certeza de que deseja excluir este registro?")
    if st.button("Sim, excluir"):
        delete_record(record_id)
        st.success("Registro excluído com sucesso")
        st.session_state.page = "Principal"
        st.experimental_rerun()
    if st.button("Não, cancelar"):
        st.session_state.page = "Principal"
        st.experimental_rerun()

# Inicialização do estado da sessão
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'page' not in st.session_state:
    st.session_state.page = "Principal"

# Inicializa o banco de dados
initialize_db()

# Lógica de navegação
if st.session_state.logged_in:
    if st.session_state.page == "Principal":
        main_page()
    elif st.session_state.page == "Editar Registro":
        edit_record_page(st.session_state.editing_record_id)
    elif st.session_state.page == "Excluir Registro":
        delete_record_page(st.session_state.deleting_record_id)
else:
    login_page()

