import tkinter as tk
from tkinter import messagebox, ttk
import sqlite3
from datetime import datetime

DB_PATH = "portaria.db"

EMPRESAS = [
    "CARDEAL",
    "EBD",
    "ATAQ",
    "MARFIM",
    "DIA",
    "TORPEDO",
    "M&S",
    "TERRA BRASIL",
    "DRUGSTORE",
    "DISPAN",
    "MIX FARMA",
    "TEIXEIRA",
    "OUTROS"
]


def forcar_maiusculo(var):
    texto = var.get()
    if texto != texto.upper():
        var.set(texto.upper())


def iniciar_tela():
    window = tk.Tk()
    window.title("Sistema de Portaria")
    window.state("zoomed")
    window.resizable(True, True)

    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    # ================= FUNÇÕES =================
    def registrar_entrada():
        if not all([
            var_motorista.get(),
            var_placa.get(),
            var_telefone.get(),
            var_fornecedor.get(),
            var_destino.get(),
            var_porteiro.get()
        ]):
            messagebox.showwarning("Atenção", "Preencha todos os campos.")
            return

        cur.execute("""
            INSERT INTO entradas
            (motorista, placa, telefone, fornecedor, destino, data_hora, porteiro)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            var_motorista.get(),
            var_placa.get(),
            var_telefone.get(),
            var_fornecedor.get(),
            var_destino.get(),
            datetime.now().strftime("%d/%m/%Y %H:%M"),
            var_porteiro.get()
        ))

        con.commit()
        limpar_campos()
        carregar_blocos()

    def registrar_saida(id_registro):
        cur.execute(
            "UPDATE entradas SET saida = ? WHERE id = ?",
            (datetime.now().strftime("%d/%m/%Y %H:%M"), id_registro)
        )
        con.commit()
        carregar_blocos()

    def limpar_campos():
        for v in vars_campos.values():
            v.set("")

    # ================= HISTÓRICO =================
    def abrir_historico():
        hist = tk.Toplevel(window)
        hist.title("Histórico de Baixas")
        hist.state("zoomed")

        frame_filtro = tk.Frame(hist, pady=10)
        frame_filtro.pack(fill="x")

        tk.Label(frame_filtro, text="Data da baixa (DD/MM/AAAA):").pack(side="left", padx=5)
        var_data = tk.StringVar()
        tk.Entry(frame_filtro, textvariable=var_data, width=15).pack(side="left", padx=5)

        tk.Label(frame_filtro, text="Empresa / Destino:").pack(side="left", padx=5)
        var_empresa = tk.StringVar()
        tk.Entry(frame_filtro, textvariable=var_empresa, width=25).pack(side="left", padx=5)

        frame_lista = tk.Frame(hist)
        frame_lista.pack(fill="both", expand=True)

        def carregar_historico():
            for w in frame_lista.winfo_children():
                w.destroy()

            query = """
                SELECT motorista, placa, telefone, fornecedor, destino,
                       data_hora, saida, porteiro
                FROM entradas
                WHERE saida IS NOT NULL
            """
            params = []

            if var_data.get():
                query += " AND saida LIKE ?"
                params.append(f"%{var_data.get()}%")

            if var_empresa.get():
                query += " AND destino LIKE ?"
                params.append(f"%{var_empresa.get().upper()}%")

            query += " ORDER BY saida DESC"

            cur.execute(query, params)
            registros = cur.fetchall()

            for r in registros:
                motorista, placa, telefone, fornecedor, destino, entrada, saida, porteiro = r

                bloco = tk.Frame(frame_lista, bd=2, relief="groove", padx=10, pady=5)
                bloco.pack(fill="x", padx=10, pady=5)

                texto = (
                    f"Motorista: {motorista}\n"
                    f"Placa: {placa}\n"
                    f"Telefone: {telefone}\n"
                    f"Fornecedor: {fornecedor}\n"
                    f"Empresa/Destino: {destino}\n"
                    f"Entrada: {entrada}\n"
                    f"Baixa: {saida}\n"
                    f"Porteiro: {porteiro}"
                )

                tk.Label(bloco, text=texto, justify="left").pack(anchor="w")

        tk.Button(frame_filtro, text="FILTRAR", command=carregar_historico).pack(side="left", padx=15)
        carregar_historico()

    # ================= BLOCOS ATIVOS =================
    def carregar_blocos():
        for w in frame_blocos.winfo_children():
            w.destroy()

        filtro = var_busca.get()

        query = """
            SELECT id, motorista, placa, telefone, fornecedor, destino, data_hora, porteiro
            FROM entradas
            WHERE saida IS NULL
        """
        params = []

        if filtro:
            query += " AND placa LIKE ?"
            params.append(f"%{filtro}%")

        query += " ORDER BY destino"

        cur.execute(query, params)
        registros = cur.fetchall()

        destinos = {}
        for r in registros:
            destinos.setdefault(r[5], []).append(r)

        for destino, itens in destinos.items():
            tk.Label(
                frame_blocos,
                text=f"DESTINO: {destino}",
                font=("Arial", 12, "bold")
            ).pack(anchor="w", padx=10, pady=(10, 0))

            for reg in itens:
                id_reg, motorista, placa, telefone, fornecedor, destino, data, porteiro = reg

                bloco = tk.Frame(frame_blocos, bd=2, relief="groove", padx=10, pady=5)
                bloco.pack(fill="x", padx=10, pady=5)

                texto = (
                    f"Motorista: {motorista}\n"
                    f"Placa: {placa}\n"
                    f"Telefone: {telefone}\n"
                    f"Fornecedor: {fornecedor}\n"
                    f"Entrada: {data}\n"
                    f"Porteiro: {porteiro}"
                )

                tk.Label(bloco, text=texto, justify="left").grid(row=0, column=0, sticky="w")

                tk.Button(
                    bloco,
                    text="REGISTRAR ENTRADA",
                    bg="#27ae60",
                    fg="white",
                    command=lambda i=id_reg: registrar_saida(i)
                ).grid(row=0, column=1, padx=15)

    # ================= FORMULÁRIO =================
    frame_form = tk.Frame(window, bd=2, relief="ridge", padx=10, pady=10)
    frame_form.pack(fill="x", padx=10, pady=10)

    campos = ["Motorista", "Placa", "Telefone", "Fornecedor", "Destino", "Porteiro"]
    vars_campos = {}

    for i, campo in enumerate(campos):
        tk.Label(frame_form, text=campo).grid(row=i, column=0, sticky="w")

        if campo == "Destino":
            var = tk.StringVar()
            combo = ttk.Combobox(
                frame_form,
                textvariable=var,
                values=EMPRESAS,
                state="readonly",
                width=38
            )
            combo.grid(row=i, column=1, padx=5, pady=3)
            vars_campos[campo] = var
        else:
            var = tk.StringVar()
            var.trace_add("write", lambda *a, v=var: forcar_maiusculo(v))
            tk.Entry(frame_form, textvariable=var, width=40).grid(
                row=i, column=1, padx=5, pady=3
            )
            vars_campos[campo] = var

    var_motorista = vars_campos["Motorista"]
    var_placa = vars_campos["Placa"]
    var_telefone = vars_campos["Telefone"]
    var_fornecedor = vars_campos["Fornecedor"]
    var_destino = vars_campos["Destino"]
    var_porteiro = vars_campos["Porteiro"]

    tk.Button(
        frame_form,
        text="REGISTRAR ENTRADA",
        bg="#2980b9",
        fg="white",
        width=25,
        command=registrar_entrada
    ).grid(row=len(campos), column=0, columnspan=2, pady=10)

    tk.Button(
        frame_form,
        text="HISTÓRICO DE BAIXAS",
        bg="#7f8c8d",
        fg="white",
        width=25,
        command=abrir_historico
    ).grid(row=len(campos) + 1, column=0, columnspan=2, pady=5)

    # ================= BUSCA =================
    frame_busca = tk.Frame(window)
    frame_busca.pack(fill="x", padx=10)

    tk.Label(frame_busca, text="Pesquisar por placa:").pack(side="left")

    var_busca = tk.StringVar()
    var_busca.trace_add("write", lambda *a: carregar_blocos())

    tk.Entry(frame_busca, textvariable=var_busca, width=20).pack(side="left", padx=5)

    # ================= LISTA =================
    frame_blocos = tk.Frame(window)
    frame_blocos.pack(fill="both", expand=True)

    carregar_blocos()
    window.mainloop()
