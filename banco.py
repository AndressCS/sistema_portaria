import sqlite3
import os


def conectar():
    caminho = os.path.abspath("portaria.db")
    print("📁 Usando banco em:", caminho)
    return sqlite3.connect(caminho)


def criar_tabela():
    con = conectar()
    cur = con.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS entradas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            motorista TEXT NOT NULL,
            placa TEXT NOT NULL,
            empresa TEXT NOT NULL,
            destino TEXT NOT NULL,
            data_hora TEXT NOT NULL,
            porteiro TEXT NOT NULL,
            saida TEXT
        )
    """)

    con.commit()
    con.close()


criar_tabela()
