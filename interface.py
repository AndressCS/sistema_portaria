import tkinter as tk
from tkinter import messagebox, ttk, simpledialog, filedialog
import sqlite3
from datetime import datetime
import re
import hashlib
import secrets

DB_PATH = "portaria.db"

EMPRESAS = [
    "CARDEAL", "EBD", "ATAQ", "MARFIM", "DIA", "TORPEDO",
    "M&S", "TERRA BRASIL", "DRUGSTORE", "DISPAN",
    "MIX FARMA", "TEIXEIRA", "OUTROS"
]


# ================= FUNÇÕES AUXILIARES =================

def forcar_maiusculo(var: tk.StringVar):
    texto = var.get()
    up = texto.upper()
    if texto != up:
        var.set(up)


def normalizar_placa(texto: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", (texto or "").upper())


def placa_valida(placa: str) -> bool:
    p = normalizar_placa(placa)
    if re.fullmatch(r"[A-Z]{3}\d{4}", p):
        return True
    if re.fullmatch(r"[A-Z]{3}\d[A-Z]\d{2}", p):
        return True
    return False


def validar_placa_digitar(texto_digitado: str) -> bool:
    if texto_digitado is None:
        return True
    t = texto_digitado.upper()
    if not re.fullmatch(r"[A-Z0-9]*", t):
        return False
    if len(t) > 7:
        return False
    return True


def normalizar_telefone(texto: str) -> str:
    return re.sub(r"\D", "", texto or "")


def validar_telefone_digitar(texto_digitado: str) -> bool:
    if texto_digitado is None:
        return True
    if not re.fullmatch(r"\d*", texto_digitado):
        return False
    if len(texto_digitado) > 15:
        return False
    return True


def hash_senha(senha: str, salt_hex: str) -> str:
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        senha.encode("utf-8"),
        bytes.fromhex(salt_hex),
        120_000
    )
    return dk.hex()


def usuario_valido(u: str) -> bool:
    return bool(re.fullmatch(r"[A-Z0-9_]{3,20}", (u or "").upper()))


# ================= INTERFACE =================

def iniciar_tela():
    window = tk.Tk()
    window.title("Sistema de Portaria")
    window.state("zoomed")
    window.resizable(True, True)

    # ✅ Conexão mais resistente a locks
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.execute("PRAGMA journal_mode=WAL;")
    con.execute("PRAGMA busy_timeout=10000;")
    cur = con.cursor()

    # ===== tabela de logs =====
    cur.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        data_hora TEXT NOT NULL,
        acao TEXT NOT NULL,
        entrada_id INTEGER,
        placa TEXT,
        destino TEXT,
        porteiro TEXT,
        detalhes TEXT
    )
    """)
    con.commit()

    # ===== tabela de usuários =====
    cur.execute("""
    CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        usuario TEXT UNIQUE NOT NULL,
        nome TEXT NOT NULL,
        salt TEXT NOT NULL,
        senha_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'PORTEIRO'
    )
    """)
    con.commit()

    # Migração: coluna ATIVO
    try:
        cur.execute("ALTER TABLE usuarios ADD COLUMN ativo INTEGER NOT NULL DEFAULT 1")
        con.commit()
    except Exception:
        pass

    def criar_usuario_se_nao_existir(usuario: str, nome: str, senha: str, role: str = "PORTEIRO"):
        usuario = (usuario or "").strip().upper()
        nome = (nome or "").strip().upper()
        role = (role or "").strip().upper()

        cur.execute("SELECT 1 FROM usuarios WHERE usuario = ?", (usuario,))
        if cur.fetchone():
            return

        salt = secrets.token_hex(16)
        senha_hash = hash_senha(senha, salt)
        cur.execute("""
            INSERT INTO usuarios (usuario, nome, salt, senha_hash, role, ativo)
            VALUES (?, ?, ?, ?, ?, 1)
        """, (usuario, nome, salt, senha_hash, role))
        con.commit()

    criar_usuario_se_nao_existir("ADMIN", "ADMIN", "ADMIN123", "ADMIN")

    usuario_logado = {"usuario": None, "nome": None, "role": None}
    baixas_em_andamento = set()
    desfazer_em_andamento = set()

    def on_close():
        try:
            con.close()
        except Exception:
            pass
        window.destroy()

    window.protocol("WM_DELETE_WINDOW", on_close)

    def registrar_log(acao, entrada_id=None, placa=None, destino=None, porteiro=None, detalhes=""):
        porteiro = (porteiro or "").strip() or "NÃO INFORMADO"
        cur.execute("""
            INSERT INTO logs (data_hora, acao, entrada_id, placa, destino, porteiro, detalhes)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            acao, entrada_id, placa, destino, porteiro, detalhes
        ))
        con.commit()

    # ================= LOGIN =================
    entry_porteiro = None

    def abrir_login():
        login = tk.Toplevel(window)
        login.title("Login")
        login.geometry("350x240")
        login.resizable(False, False)
        login.grab_set()

        # ✅ se fechar login sem autenticar -> fecha o sistema
        def bloquear_sem_login():
            if usuario_logado.get("usuario") is None:
                try:
                    window.destroy()
                except Exception:
                    pass

        login.protocol("WM_DELETE_WINDOW", bloquear_sem_login)

        tk.Label(login, text="Usuário:").pack(pady=(15, 2))
        var_user = tk.StringVar()
        e_user = tk.Entry(login, textvariable=var_user)
        e_user.pack()

        tk.Label(login, text="Senha:").pack(pady=(10, 2))
        var_pass = tk.StringVar()
        e_pass = tk.Entry(login, textvariable=var_pass, show="*")
        e_pass.pack()

        lbl_status = tk.Label(login, text="", fg="red")
        lbl_status.pack(pady=10)

        def tentar_login():
            u = (var_user.get() or "").strip().upper()
            p = (var_pass.get() or "").strip()

            if not u or not p:
                lbl_status.config(text="Informe usuário e senha.")
                return

            cur.execute("""
                SELECT usuario, nome, salt, senha_hash, role, ativo
                FROM usuarios
                WHERE usuario = ?
            """, (u,))
            row = cur.fetchone()
            if not row:
                lbl_status.config(text="Usuário não encontrado.")
                return

            usuario_db, nome_db, salt_db, hash_db, role_db, ativo_db = row
            if int(ativo_db) != 1:
                lbl_status.config(text="Usuário desativado.")
                return

            if hash_senha(p, salt_db) != hash_db:
                lbl_status.config(text="Senha incorreta.")
                return

            usuario_logado["usuario"] = usuario_db
            usuario_logado["nome"] = nome_db
            usuario_logado["role"] = role_db

            var_porteiro.set(nome_db)
            if entry_porteiro is not None:
                entry_porteiro.config(state="disabled")

            login.destroy()

        tk.Button(login, text="ENTRAR", width=18, command=tentar_login).pack(pady=5)

        def ao_enter(event):
            tentar_login()

        e_user.bind("<Return>", ao_enter)
        e_pass.bind("<Return>", ao_enter)
        e_user.focus_set()

    def logout():
        if not messagebox.askyesno("Trocar usuário", "Deseja trocar o usuário logado?"):
            return

        if usuario_logado.get("nome"):
            registrar_log(
                acao="LOGOUT",
                porteiro=usuario_logado.get("nome"),
                detalhes=f"TROCOU USUÁRIO (de {usuario_logado.get('usuario')})"
            )

        usuario_logado["usuario"] = None
        usuario_logado["nome"] = None
        usuario_logado["role"] = None

        try:
            entry_porteiro.config(state="normal")
        except Exception:
            pass
        var_porteiro.set("")

        abrir_login()

    # ================= TELA DE CADASTRO (ADMIN) =================
    def abrir_cadastro_usuarios():
        if usuario_logado.get("role") != "ADMIN":
            messagebox.showwarning("Acesso negado", "Apenas ADMIN pode gerenciar usuários.")
            return

        win = tk.Toplevel(window)
        win.title("Cadastro de Usuários")
        win.state("zoomed")

        topo = tk.Frame(win, pady=10)
        topo.pack(fill="x")
        tk.Label(topo, text="Usuários do Sistema", font=("Arial", 14, "bold")).pack(side="left", padx=10)

        frame_lista = tk.Frame(win, padx=10, pady=10)
        frame_lista.pack(fill="both", expand=True)

        cols = ("usuario", "nome", "role", "ativo")
        tree = ttk.Treeview(frame_lista, columns=cols, show="headings")
        tree.heading("usuario", text="USUÁRIO")
        tree.heading("nome", text="NOME")
        tree.heading("role", text="PERFIL")
        tree.heading("ativo", text="ATIVO")

        tree.column("usuario", width=140, anchor="w")
        tree.column("nome", width=260, anchor="w")
        tree.column("role", width=120, anchor="center")
        tree.column("ativo", width=80, anchor="center")

        # ✅ GRID para scroll sempre funcionar
        frame_lista.grid_rowconfigure(0, weight=1)
        frame_lista.grid_columnconfigure(0, weight=1)

        tree.grid(row=0, column=0, sticky="nsew")

        scroll_y = ttk.Scrollbar(frame_lista, orient="vertical", command=tree.yview)
        scroll_y.grid(row=0, column=1, sticky="ns")

        scroll_x = ttk.Scrollbar(frame_lista, orient="horizontal", command=tree.xview)
        scroll_x.grid(row=1, column=0, sticky="ew")

        tree.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)

        frame_btn = tk.Frame(win, pady=10)
        frame_btn.pack(fill="x")

        def carregar_usuarios():
            for item in tree.get_children():
                tree.delete(item)
            cur.execute("SELECT usuario, nome, role, ativo FROM usuarios ORDER BY usuario")
            for u, n, r, a in cur.fetchall():
                tree.insert("", "end", values=(u, n, r, "SIM" if int(a) == 1 else "NÃO"))

        def get_sel():
            sel = tree.selection()
            if not sel:
                return None
            return tree.item(sel[0], "values")

        def novo_usuario():
            u = simpledialog.askstring("Novo usuário", "Usuário (A-Z, 0-9, _), 3-20:", parent=win)
            if u is None:
                return
            u = u.strip().upper()
            if not usuario_valido(u):
                messagebox.showwarning("Usuário inválido", "Use apenas A-Z, 0-9 e _. Tamanho 3 a 20.")
                return

            n = simpledialog.askstring("Novo usuário", "Nome completo:", parent=win)
            if n is None:
                return
            n = n.strip().upper()
            if not n:
                messagebox.showwarning("Nome inválido", "Informe o nome.")
                return

            senha = simpledialog.askstring("Novo usuário", "Senha inicial:", show="*", parent=win)
            if senha is None:
                return
            if len(senha) < 4:
                messagebox.showwarning("Senha fraca", "A senha deve ter pelo menos 4 caracteres.")
                return

            role = simpledialog.askstring("Novo usuário", "Perfil (PORTEIRO ou ADMIN):", parent=win)
            if role is None:
                return
            role = role.strip().upper()
            if role not in ("PORTEIRO", "ADMIN"):
                messagebox.showwarning("Perfil inválido", "Use PORTEIRO ou ADMIN.")
                return

            try:
                salt = secrets.token_hex(16)
                senha_hash = hash_senha(senha, salt)
                cur.execute("""
                    INSERT INTO usuarios (usuario, nome, salt, senha_hash, role, ativo)
                    VALUES (?, ?, ?, ?, ?, 1)
                """, (u, n, salt, senha_hash, role))
                con.commit()

                registrar_log("USER_CREATE", porteiro=usuario_logado.get("nome"),
                              detalhes=f"CRIADO: usuario={u} nome={n} role={role}")
                carregar_usuarios()
                messagebox.showinfo("Sucesso", f"Usuário {u} criado.")
            except sqlite3.IntegrityError:
                messagebox.showwarning("Já existe", "Este usuário já existe.")
            except Exception as e:
                messagebox.showerror("Erro", str(e))

        def reset_senha():
            sel = get_sel()
            if not sel:
                messagebox.showwarning("Selecione", "Selecione um usuário.")
                return
            u, n, r, a = sel

            senha = simpledialog.askstring("Resetar senha", f"Nova senha para {u}:", show="*", parent=win)
            if senha is None:
                return
            if len(senha) < 4:
                messagebox.showwarning("Senha fraca", "A senha deve ter pelo menos 4 caracteres.")
                return

            salt = secrets.token_hex(16)
            senha_hash = hash_senha(senha, salt)
            cur.execute("UPDATE usuarios SET salt=?, senha_hash=? WHERE usuario=?", (salt, senha_hash, u))
            con.commit()

            registrar_log("USER_RESET_PASS", porteiro=usuario_logado.get("nome"), detalhes=f"RESET SENHA: usuario={u}")
            messagebox.showinfo("Ok", f"Senha do usuário {u} atualizada.")

        def trocar_role():
            sel = get_sel()
            if not sel:
                messagebox.showwarning("Selecione", "Selecione um usuário.")
                return
            u, n, r, a = sel

            novo = simpledialog.askstring("Trocar perfil", f"Novo perfil para {u} (PORTEIRO/ADMIN):", parent=win)
            if novo is None:
                return
            novo = novo.strip().upper()
            if novo not in ("PORTEIRO", "ADMIN"):
                messagebox.showwarning("Perfil inválido", "Use PORTEIRO ou ADMIN.")
                return

            cur.execute("UPDATE usuarios SET role=? WHERE usuario=?", (novo, u))
            con.commit()

            registrar_log("USER_ROLE", porteiro=usuario_logado.get("nome"),
                          detalhes=f"ROLE: usuario={u} de={r} para={novo}")
            carregar_usuarios()

        def ativar_desativar():
            sel = get_sel()
            if not sel:
                messagebox.showwarning("Selecione", "Selecione um usuário.")
                return
            u, n, r, a = sel

            if u == (usuario_logado.get("usuario") or ""):
                messagebox.showwarning("Não permitido", "Você não pode desativar o usuário logado.")
                return

            ativo_atual = 1 if a == "SIM" else 0
            novo_ativo = 0 if ativo_atual == 1 else 1
            acao_txt = "DESATIVAR" if novo_ativo == 0 else "ATIVAR"

            if not messagebox.askyesno("Confirmar", f"Deseja {acao_txt} o usuário {u}?"):
                return

            cur.execute("UPDATE usuarios SET ativo=? WHERE usuario=?", (novo_ativo, u))
            con.commit()

            registrar_log("USER_ACTIVE", porteiro=usuario_logado.get("nome"),
                          detalhes=f"ATIVO: usuario={u} para={'SIM' if novo_ativo == 1 else 'NÃO'}")
            carregar_usuarios()

        ttk.Button(frame_btn, text="NOVO USUÁRIO", command=novo_usuario).pack(side="left", padx=10)
        ttk.Button(frame_btn, text="RESETAR SENHA", command=reset_senha).pack(side="left", padx=10)
        ttk.Button(frame_btn, text="TROCAR PERFIL", command=trocar_role).pack(side="left", padx=10)
        ttk.Button(frame_btn, text="ATIVAR/DESATIVAR", command=ativar_desativar).pack(side="left", padx=10)
        ttk.Button(frame_btn, text="ATUALIZAR LISTA", command=carregar_usuarios).pack(side="right", padx=10)

        carregar_usuarios()

    # ================= FORMULÁRIO =================
    frame_form = tk.Frame(window, bd=2, relief="ridge", padx=10, pady=10)
    frame_form.pack(fill="x", padx=10, pady=10)

    campos = ["Motorista", "Placa", "Telefone", "Fornecedor", "Destino", "Porteiro"]
    vars_campos = {}

    linha = 0
    for campo in campos:
        tk.Label(frame_form, text=campo).grid(row=linha, column=0, sticky="w")

        if campo == "Destino":
            var = tk.StringVar()
            combo_destino = ttk.Combobox(frame_form, textvariable=var, values=EMPRESAS, state="readonly", width=38)
            combo_destino.grid(row=linha, column=1, padx=5, pady=3)
            vars_campos[campo] = var

        elif campo == "Placa":
            var = tk.StringVar()
            vcmd = (window.register(validar_placa_digitar), "%P")
            entry_placa = tk.Entry(frame_form, textvariable=var, width=40, validate="key", validatecommand=vcmd)
            entry_placa.grid(row=linha, column=1, padx=5, pady=3)
            vars_campos[campo] = var

        elif campo == "Telefone":
            var = tk.StringVar()
            vcmd_tel = (window.register(validar_telefone_digitar), "%P")
            tk.Entry(frame_form, textvariable=var, width=40, validate="key", validatecommand=vcmd_tel)\
                .grid(row=linha, column=1, padx=5, pady=3)
            vars_campos[campo] = var

        else:
            var = tk.StringVar()
            var.trace_add("write", lambda *a, v=var: forcar_maiusculo(v))
            if campo == "Porteiro":
                entry_porteiro = tk.Entry(frame_form, textvariable=var, width=40)
                entry_porteiro.grid(row=linha, column=1, padx=5, pady=3)
            else:
                tk.Entry(frame_form, textvariable=var, width=40).grid(row=linha, column=1, padx=5, pady=3)
            vars_campos[campo] = var

        linha += 1

    var_motorista = vars_campos["Motorista"]
    var_placa = vars_campos["Placa"]
    var_telefone = vars_campos["Telefone"]
    var_fornecedor = vars_campos["Fornecedor"]
    var_destino = vars_campos["Destino"]
    var_porteiro = vars_campos["Porteiro"]

    # ✅ Garante maiúsculo também no campo placa (e sem loop)
    def _placa_upper():
        placa_norm = normalizar_placa(var_placa.get())
        if var_placa.get() != placa_norm:
            var_placa.set(placa_norm)

    # ================= AUTO-PREENCHIMENTO POR PLACA =================
    def autopreencher_por_placa():
        placa_norm = normalizar_placa(var_placa.get())

        # normaliza/força uppercase enquanto digita
        if var_placa.get() != placa_norm:
            var_placa.set(placa_norm)
            return

        # só tenta buscar quando tiver tamanho de placa completa
        if len(placa_norm) < 7:
            return

        try:
            cur.execute("""
                SELECT motorista, telefone, fornecedor
                FROM entradas
                WHERE placa = ?
                ORDER BY id DESC
                LIMIT 1
            """, (placa_norm,))
            row = cur.fetchone()
            if not row:
                return

            motorista_db, telefone_db, fornecedor_db = row

            # não sobrescreve se já tiver preenchido
            if not var_motorista.get():
                var_motorista.set(motorista_db or "")
            if not var_telefone.get():
                var_telefone.set(telefone_db or "")
            if not var_fornecedor.get():
                var_fornecedor.set(fornecedor_db or "")
        except Exception:
            pass

    # 🔗 liga o trace da placa: maiúsculo + autopreencher
    var_placa.trace_add("write", lambda *a: autopreencher_por_placa())

    # ================= FUNÇÕES DE ENTRADA / LIMPAR =================
    def limpar_campos():
        var_motorista.set("")
        var_placa.set("")
        var_telefone.set("")
        var_fornecedor.set("")
        combo_destino.set("")
        # porteiro fica travado

    def registrar_entrada():
        try:
            placa_norm = normalizar_placa(var_placa.get())
            var_placa.set(placa_norm)

            tel_norm = normalizar_telefone(var_telefone.get())
            var_telefone.set(tel_norm)

            if not placa_valida(placa_norm):
                messagebox.showwarning("Placa inválida", "Formato: ABC1234 ou ABC1D23")
                return

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

            cur.execute("SELECT id FROM entradas WHERE placa = ? AND saida IS NULL", (var_placa.get(),))
            if cur.fetchone():
                messagebox.showwarning("Placa já registrada", "Este veículo já possui ENTRADA ATIVA.")
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

            registrar_log(
                acao="ENTRADA",
                placa=var_placa.get(),
                destino=var_destino.get(),
                porteiro=usuario_logado.get("nome") or var_porteiro.get(),
                detalhes=f"FORNECEDOR={var_fornecedor.get()} TEL={var_telefone.get()}"
            )

            limpar_campos()
            carregar_blocos()

        except Exception as e:
            messagebox.showerror("Erro ao registrar entrada", str(e))

    # ================= BAIXA / DESFAZER =================
    def registrar_saida(id_registro):
        if id_registro in baixas_em_andamento:
            return
        baixas_em_andamento.add(id_registro)
        try:
            if not messagebox.askyesno("Confirmar baixa", "Deseja realmente registrar a saída deste veículo?"):
                return

            cur.execute("SELECT placa, destino FROM entradas WHERE id = ?", (id_registro,))
            row = cur.fetchone()
            placa_, destino_ = (row[0], row[1]) if row else ("", "")

            cur.execute("UPDATE entradas SET saida = ? WHERE id = ?",
                        (datetime.now().strftime("%d/%m/%Y %H:%M"), id_registro))
            con.commit()

            registrar_log("BAIXA", entrada_id=id_registro, placa=placa_, destino=destino_,
                          porteiro=usuario_logado.get("nome") or var_porteiro.get(), detalhes="REGISTRO DE SAÍDA")
            carregar_blocos()
        except Exception as e:
            messagebox.showerror("Erro ao registrar saída", str(e))
        finally:
            baixas_em_andamento.discard(id_registro)

    def desfazer_baixa(id_registro):
        if usuario_logado.get("role") != "ADMIN":
            messagebox.showwarning("Acesso negado", "Apenas ADMIN pode desfazer baixa.")
            return

        if id_registro in desfazer_em_andamento:
            return
        desfazer_em_andamento.add(id_registro)

        try:
            if not messagebox.askyesno("Desfazer baixa", "Deseja DESFAZER a baixa deste veículo?"):
                return

            cur.execute("SELECT placa, destino FROM entradas WHERE id = ?", (id_registro,))
            row = cur.fetchone()
            placa_, destino_ = (row[0], row[1]) if row else ("", "")

            cur.execute("UPDATE entradas SET saida = NULL WHERE id = ?", (id_registro,))
            con.commit()

            registrar_log("DESFAZER_BAIXA", entrada_id=id_registro, placa=placa_, destino=destino_,
                          porteiro=usuario_logado.get("nome"), detalhes="BAIXA DESFEITA")
            carregar_blocos()
        except Exception as e:
            messagebox.showerror("Erro ao desfazer baixa", str(e))
        finally:
            desfazer_em_andamento.discard(id_registro)

    # ================= HISTÓRICO / LOGS =================
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
        var_empresa.trace_add("write", lambda *a: forcar_maiusculo(var_empresa))
        tk.Entry(frame_filtro, textvariable=var_empresa, width=25).pack(side="left", padx=5)

        frame_lista = tk.Frame(hist)
        frame_lista.pack(fill="both", expand=True)

        def carregar_historico():
            for w in frame_lista.winfo_children():
                w.destroy()

            query = """
                SELECT id, motorista, placa, telefone, fornecedor, destino,
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
                params.append(f"%{var_empresa.get()}%")
            query += " ORDER BY saida DESC"

            cur.execute(query, params)
            for r in cur.fetchall():
                id_reg, motorista, placa, telefone, fornecedor, destino, entrada, saida, porteiro = r
                bloco = tk.Frame(frame_lista, bd=2, relief="groove", padx=10, pady=5)
                bloco.pack(fill="x", padx=10, pady=5)

                texto = (
                    f"Motorista: {motorista}\n"
                    f"Placa: {placa}\n"
                    f"Telefone: {telefone}\n"
                    f"Fornecedor: {fornecedor}\n"
                    f"Destino: {destino}\n"
                    f"Entrada: {entrada}\n"
                    f"Baixa: {saida}\n"
                    f"Porteiro (entrada): {porteiro}"
                )
                tk.Label(bloco, text=texto, justify="left").pack(anchor="w")

                tk.Button(
                    bloco, text="DESFAZER BAIXA",
                    bg="#e67e22", fg="white",
                    command=lambda i=id_reg: desfazer_baixa(i)
                ).pack(anchor="e", padx=10, pady=5)

        tk.Button(frame_filtro, text="FILTRAR", command=carregar_historico).pack(side="left", padx=15)
        carregar_historico()

    def abrir_logs():
        logw = tk.Toplevel(window)
        logw.title("Logs do Sistema")
        logw.state("zoomed")

        frame_filtro = tk.Frame(logw, pady=10)
        frame_filtro.pack(fill="x")

        tk.Label(frame_filtro, text="Data (DD/MM/AAAA):").pack(side="left", padx=5)
        var_data = tk.StringVar()
        tk.Entry(frame_filtro, textvariable=var_data, width=15).pack(side="left", padx=5)

        tk.Label(frame_filtro, text="Placa:").pack(side="left", padx=5)
        var_placa_f = tk.StringVar()
        var_placa_f.trace_add("write", lambda *a: forcar_maiusculo(var_placa_f))
        tk.Entry(frame_filtro, textvariable=var_placa_f, width=12).pack(side="left", padx=5)

        tk.Label(frame_filtro, text="Porteiro:").pack(side="left", padx=5)
        var_porteiro_f = tk.StringVar()
        var_porteiro_f.trace_add("write", lambda *a: forcar_maiusculo(var_porteiro_f))
        tk.Entry(frame_filtro, textvariable=var_porteiro_f, width=18).pack(side="left", padx=5)

        tk.Label(frame_filtro, text="Ação:").pack(side="left", padx=5)
        var_acao = tk.StringVar(value="TODAS")
        combo_acao = ttk.Combobox(
            frame_filtro,
            textvariable=var_acao,
            values=["TODAS", "ENTRADA", "BAIXA", "DESFAZER_BAIXA", "LOGOUT",
                    "USER_CREATE", "USER_RESET_PASS", "USER_ROLE", "USER_ACTIVE"],
            state="readonly",
            width=18
        )
        combo_acao.pack(side="left", padx=5)

        frame_lista = tk.Frame(logw)
        frame_lista.pack(fill="both", expand=True)

        def carregar_logs():
            for w in frame_lista.winfo_children():
                w.destroy()

            query = """
                SELECT id, data_hora, acao, entrada_id, placa, destino, porteiro, detalhes
                FROM logs
                WHERE 1=1
            """
            params = []
            if var_data.get():
                query += " AND data_hora LIKE ?"
                params.append(f"%{var_data.get()}%")
            if var_placa_f.get():
                query += " AND placa LIKE ?"
                params.append(f"%{var_placa_f.get()}%")
            if var_porteiro_f.get():
                query += " AND porteiro LIKE ?"
                params.append(f"%{var_porteiro_f.get()}%")
            if var_acao.get() != "TODAS":
                query += " AND acao = ?"
                params.append(var_acao.get())
            query += " ORDER BY id DESC"

            cur.execute(query, params)
            for r in cur.fetchall():
                _id, data_hora, acao, entrada_id, placa, destino, porteiro, detalhes = r
                bloco = tk.Frame(frame_lista, bd=2, relief="groove", padx=10, pady=5)
                bloco.pack(fill="x", padx=10, pady=5)
                texto = (
                    f"Data/Hora: {data_hora}\n"
                    f"Ação: {acao}\n"
                    f"Entrada ID: {entrada_id}\n"
                    f"Placa: {placa}\n"
                    f"Destino: {destino}\n"
                    f"Porteiro: {porteiro}\n"
                    f"Detalhes: {detalhes}"
                )
                tk.Label(bloco, text=texto, justify="left").pack(anchor="w")

        tk.Button(frame_filtro, text="FILTRAR", command=carregar_logs).pack(side="left", padx=15)
        carregar_logs()

    # ================= RELATÓRIOS + EXPORTAÇÃO =================
    def _parse_dt(s: str):
        if not s:
            return None
        s = s.strip()
        for fmt in ("%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M", "%d/%m/%Y"):
            try:
                return datetime.strptime(s, fmt)
            except ValueError:
                pass
        return None

    def _parse_data_simples(s: str):
        # aceita "DD/MM/AAAA" (opcionalmente com hora)
        if not s:
            return None
        s = s.strip()
        for fmt in ("%d/%m/%Y", "%d/%m/%Y %H:%M", "%d/%m/%Y %H:%M:%S"):
            try:
                return datetime.strptime(s, fmt)
            except ValueError:
                pass
        return None

    def abrir_relatorios():
        rel = tk.Toplevel(window)
        rel.title("Relatórios e Exportação")
        rel.state("zoomed")

        # ===== filtros =====
        frame_filtro = tk.Frame(rel, padx=10, pady=10, bd=2, relief="groove")
        frame_filtro.pack(fill="x", padx=10, pady=10)

        tk.Label(frame_filtro, text="Período (DD/MM/AAAA)").grid(row=0, column=0, sticky="w")
        tk.Label(frame_filtro, text="Início:").grid(row=1, column=0, sticky="e")
        var_ini = tk.StringVar()
        e_ini = tk.Entry(frame_filtro, textvariable=var_ini, width=12)
        e_ini.grid(row=1, column=1, padx=5)

        tk.Label(frame_filtro, text="Fim:").grid(row=1, column=2, sticky="e")
        var_fim = tk.StringVar()
        e_fim = tk.Entry(frame_filtro, textvariable=var_fim, width=12)
        e_fim.grid(row=1, column=3, padx=5)

        tk.Label(frame_filtro, text="Status:").grid(row=1, column=4, sticky="e")
        var_status = tk.StringVar(value="TODOS")
        cb_status = ttk.Combobox(frame_filtro, textvariable=var_status, state="readonly",
                                 values=["TODOS", "ATIVOS", "BAIXADOS"], width=10)
        cb_status.grid(row=1, column=5, padx=5)

        tk.Label(frame_filtro, text="Empresa/Destino:").grid(row=2, column=0, sticky="e")
        var_dest = tk.StringVar()
        var_dest.trace_add("write", lambda *a: forcar_maiusculo(var_dest))
        e_dest = tk.Entry(frame_filtro, textvariable=var_dest, width=22)
        e_dest.grid(row=2, column=1, padx=5, sticky="w")

        tk.Label(frame_filtro, text="Fornecedor:").grid(row=2, column=2, sticky="e")
        var_forn = tk.StringVar()
        var_forn.trace_add("write", lambda *a: forcar_maiusculo(var_forn))
        e_forn = tk.Entry(frame_filtro, textvariable=var_forn, width=22)
        e_forn.grid(row=2, column=3, padx=5, sticky="w")

        tk.Label(frame_filtro, text="Porteiro:").grid(row=2, column=4, sticky="e")
        var_port = tk.StringVar()
        var_port.trace_add("write", lambda *a: forcar_maiusculo(var_port))
        e_port = tk.Entry(frame_filtro, textvariable=var_port, width=18)
        e_port.grid(row=2, column=5, padx=5, sticky="w")

        tk.Label(frame_filtro, text="Filtrar por data de:").grid(row=0, column=4, sticky="e")
        var_tipo_data = tk.StringVar(value="ENTRADA")
        cb_tipo = ttk.Combobox(frame_filtro, textvariable=var_tipo_data, state="readonly",
                               values=["ENTRADA", "BAIXA"], width=10)
        cb_tipo.grid(row=0, column=5, padx=5, sticky="w")

        # ===== resumo =====
        frame_resumo = tk.Frame(rel, padx=10, pady=6)
        frame_resumo.pack(fill="x")

        lbl_total = tk.Label(frame_resumo, text="Total: 0", font=("Arial", 11, "bold"))
        lbl_total.pack(side="left", padx=5)

        lbl_ativos = tk.Label(frame_resumo, text="Ativos: 0")
        lbl_ativos.pack(side="left", padx=15)

        lbl_baixados = tk.Label(frame_resumo, text="Baixados: 0")
        lbl_baixados.pack(side="left", padx=15)

        lbl_por_emp = tk.Label(frame_resumo, text="Por empresa: -")
        lbl_por_emp.pack(side="left", padx=15)

        # ===== tabela =====
        frame_lista = tk.Frame(rel, padx=10, pady=10)
        frame_lista.pack(fill="both", expand=True)

        cols = ("id", "motorista", "placa", "telefone", "fornecedor", "destino", "entrada", "saida", "porteiro")
        tree = ttk.Treeview(frame_lista, columns=cols, show="headings")
        for c in cols:
            tree.heading(c, text=c.upper())

        tree.column("id", width=60, anchor="center")
        tree.column("motorista", width=200)
        tree.column("placa", width=90, anchor="center")
        tree.column("telefone", width=110, anchor="center")
        tree.column("fornecedor", width=160)
        tree.column("destino", width=140)
        tree.column("entrada", width=140, anchor="center")
        tree.column("saida", width=140, anchor="center")
        tree.column("porteiro", width=140)

        frame_lista.grid_rowconfigure(0, weight=1)
        frame_lista.grid_columnconfigure(0, weight=1)
        tree.grid(row=0, column=0, sticky="nsew")

        sy = ttk.Scrollbar(frame_lista, orient="vertical", command=tree.yview)
        sy.grid(row=0, column=1, sticky="ns")
        sx = ttk.Scrollbar(frame_lista, orient="horizontal", command=tree.xview)
        sx.grid(row=1, column=0, sticky="ew")
        tree.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)

        dados_atual = []  # guarda as linhas para exportar

        def carregar_relatorio():
            nonlocal dados_atual
            for i in tree.get_children():
                tree.delete(i)
            dados_atual = []

            ini = _parse_data_simples(var_ini.get())
            fim = _parse_data_simples(var_fim.get())
            if ini and fim and ini > fim:
                messagebox.showwarning("Período inválido", "Data inicial maior que data final.")
                return

            # query base
            q = """
                SELECT id, motorista, placa, telefone, fornecedor, destino, data_hora, saida, porteiro
                FROM entradas
                WHERE 1=1
            """
            params = []

            st = var_status.get()
            if st == "ATIVOS":
                q += " AND saida IS NULL"
            elif st == "BAIXADOS":
                q += " AND saida IS NOT NULL"

            if var_dest.get().strip():
                q += " AND destino LIKE ?"
                params.append(f"%{var_dest.get().strip().upper()}%")

            if var_forn.get().strip():
                q += " AND fornecedor LIKE ?"
                params.append(f"%{var_forn.get().strip().upper()}%")

            if var_port.get().strip():
                q += " AND porteiro LIKE ?"
                params.append(f"%{var_port.get().strip().upper()}%")

            q += " ORDER BY id DESC"
            cur.execute(q, params)
            rows = cur.fetchall()

            # filtro de período em Python (porque as datas estão como texto BR)
            tipo = var_tipo_data.get()
            filtrado = []
            for r in rows:
                id_, mot, pla, tel, forn, dest, entrada, saida, port = r
                dt_str = entrada if tipo == "ENTRADA" else saida
                dt = _parse_dt(dt_str) if dt_str else None

                if ini and dt:
                    if dt < ini:
                        continue
                if fim and dt:
                    # inclui o dia final inteiro
                    fim_fechamento = fim.replace(hour=23, minute=59, second=59)
                    if dt > fim_fechamento:
                        continue

                # se tipo == BAIXA e a linha não tem baixa, ignora quando período está preenchido
                if tipo == "BAIXA" and (var_ini.get().strip() or var_fim.get().strip()) and not saida:
                    continue

                filtrado.append(r)

            # preencher tabela
            for r in filtrado:
                tree.insert("", "end", values=r)
            dados_atual = filtrado

            # resumo
            total = len(filtrado)
            ativos = sum(1 for r in filtrado if r[7] is None)
            baixados = total - ativos

            # por empresa/destino (top 3)
            cont = {}
            for r in filtrado:
                d = (r[5] or "").strip().upper()
                cont[d] = cont.get(d, 0) + 1
            top = sorted(cont.items(), key=lambda x: x[1], reverse=True)[:3]
            top_txt = ", ".join([f"{k}:{v}" for k, v in top]) if top else "-"

            lbl_total.config(text=f"Total: {total}")
            lbl_ativos.config(text=f"Ativos: {ativos}")
            lbl_baixados.config(text=f"Baixados: {baixados}")
            lbl_por_emp.config(text=f"Por empresa: {top_txt}")

        def exportar_csv():
            if not dados_atual:
                messagebox.showwarning("Nada para exportar", "Gere o relatório antes de exportar.")
                return

            arquivo = filedialog.asksaveasfilename(
                parent=rel,
                defaultextension=".csv",
                filetypes=[("CSV", "*.csv")],
                title="Salvar relatório como CSV"
            )
            if not arquivo:
                return

            try:
                import csv
                with open(arquivo, "w", newline="", encoding="utf-8-sig") as f:
                    w = csv.writer(f, delimiter=";")
                    w.writerow(["id", "motorista", "placa", "telefone", "fornecedor", "destino", "entrada", "saida", "porteiro"])
                    for r in dados_atual:
                        w.writerow(list(r))

                messagebox.showinfo("Exportado", f"Relatório salvo em:\n{arquivo}")
            except Exception as e:
                messagebox.showerror("Erro ao exportar", str(e))

        frame_btn = tk.Frame(rel, pady=10)
        frame_btn.pack(fill="x")

        ttk.Button(frame_btn, text="GERAR RELATÓRIO", command=carregar_relatorio).pack(side="left", padx=10)
        ttk.Button(frame_btn, text="EXPORTAR CSV", command=exportar_csv).pack(side="left", padx=10)

        # carregar de primeira (opcional)
        carregar_relatorio()


    # ================= BOTÕES PRINCIPAIS =================
    tk.Button(frame_form, text="REGISTRAR ENTRADA", bg="#2980b9", fg="white", width=25,
              command=registrar_entrada).grid(row=linha, column=0, columnspan=2, pady=10)

    tk.Button(frame_form, text="HISTÓRICO DE BAIXAS", bg="#7f8c8d", fg="white", width=25,
              command=abrir_historico).grid(row=linha + 1, column=0, columnspan=2, pady=5)

    tk.Button(frame_form, text="LOGS DO SISTEMA", bg="#34495e", fg="white", width=25,
              command=abrir_logs).grid(row=linha + 2, column=0, columnspan=2, pady=5)

    tk.Button(frame_form, text="USUÁRIOS (CADASTRO)", bg="#8e44ad", fg="white", width=25,
              command=abrir_cadastro_usuarios).grid(row=linha + 3, column=0, columnspan=2, pady=5)

    tk.Button(frame_form, text="TROCAR USUÁRIO", bg="#c0392b", fg="white", width=25,
              command=logout).grid(row=linha + 4, column=0, columnspan=2, pady=5)

    tk.Button(frame_form, text="RELATÓRIOS / EXPORTAR", bg="#16a085", fg="white", width=25,
              command=abrir_relatorios).grid(row=linha + 5, column=0, columnspan=2, pady=5)

    # ================= BUSCA =================
    frame_busca = tk.Frame(window)
    frame_busca.pack(fill="x", padx=10)

    tk.Label(frame_busca, text="Pesquisar por placa ou empresa:").pack(side="left")

    var_busca = tk.StringVar()
    var_busca.trace_add("write", lambda *a: (forcar_maiusculo(var_busca), carregar_blocos()))
    tk.Entry(frame_busca, textvariable=var_busca, width=25).pack(side="left", padx=5)

    # ================= ÁREA DE BLOCOS (HORIZONTAL + SCROLL) =================
    blocos_container = tk.Frame(window)
    blocos_container.pack(fill="both", expand=True)

    canvas_blocos = tk.Canvas(blocos_container)
    canvas_blocos.pack(side="left", fill="both", expand=True)

    scroll_y_blocos = ttk.Scrollbar(blocos_container, orient="vertical", command=canvas_blocos.yview)
    scroll_y_blocos.pack(side="right", fill="y")

    scroll_x_blocos = ttk.Scrollbar(window, orient="horizontal", command=canvas_blocos.xview)
    scroll_x_blocos.pack(fill="x")

    canvas_blocos.configure(yscrollcommand=scroll_y_blocos.set, xscrollcommand=scroll_x_blocos.set)

    frame_blocos = tk.Frame(canvas_blocos)
    canvas_window_id = canvas_blocos.create_window((0, 0), window=frame_blocos, anchor="nw")

    def _ajustar_scroll_blocos(event=None):
        canvas_blocos.configure(scrollregion=canvas_blocos.bbox("all"))

    frame_blocos.bind("<Configure>", _ajustar_scroll_blocos)

    def _on_canvas_configure(event):
        canvas_blocos.itemconfig(canvas_window_id)

    canvas_blocos.bind("<Configure>", _on_canvas_configure)

    # ================= BLOCOS ATIVOS (COLUNAS + CARDS EM HORIZONTAL) =================
    def carregar_blocos():
        for w in frame_blocos.winfo_children():
            w.destroy()

        filtro = var_busca.get().strip().upper()

        query = """
            SELECT id, motorista, placa, telefone, fornecedor, destino, data_hora, porteiro
            FROM entradas
            WHERE saida IS NULL
        """
        params = []
        if filtro:
            query += " AND (placa LIKE ? OR destino LIKE ?)"
            params.extend([f"%{filtro}%", f"%{filtro}%"])

        query += " ORDER BY destino, data_hora"
        cur.execute(query, params)
        registros = cur.fetchall()

        por_destino = {}
        for r in registros:
            por_destino.setdefault(r[5], []).append(r)

        destinos_ordenados = [d for d in EMPRESAS if d in por_destino]
        for d in por_destino.keys():
            if d not in destinos_ordenados:
                destinos_ordenados.append(d)

        CARDS_POR_LINHA = 2  # ajuste se quiser 3

        for col, destino in enumerate(destinos_ordenados):
            coluna = tk.Frame(frame_blocos, bd=2, relief="groove", padx=10, pady=10)
            coluna.grid(row=0, column=col, padx=10, pady=10, sticky="n")

            tk.Label(coluna, text=destino, font=("Arial", 12, "bold")).pack(anchor="center", pady=(0, 8))

            cards_area = tk.Frame(coluna)
            cards_area.pack()

            itens = por_destino.get(destino, [])
            if not itens:
                tk.Label(cards_area, text="(sem entradas)", fg="gray").grid(row=0, column=0)
                continue

            for idx, reg in enumerate(itens, start=1):
                id_reg, motorista, placa, telefone, fornecedor, _dest, data, porteiro = reg

                pos = idx - 1
                r = pos // CARDS_POR_LINHA
                c = pos % CARDS_POR_LINHA

                card = tk.Frame(cards_area, bd=1, relief="solid", padx=8, pady=6)
                card.grid(row=r, column=c, padx=8, pady=8, sticky="n")

                tk.Label(card, text=f"{idx}) {placa} - {motorista}", font=("Arial", 10, "bold")).pack(anchor="w")
                tk.Label(card, text=f"TEL: {telefone} | FORN: {fornecedor}").pack(anchor="w")
                tk.Label(card, text=f"ENTRADA: {data} | PORTEIRO: {porteiro}").pack(anchor="w")

                tk.Button(
                    card, text="REGISTRAR SAÍDA",
                    bg="#27ae60", fg="white",
                    command=lambda i=id_reg: registrar_saida(i)
                ).pack(anchor="e", pady=(6, 0))

        _ajustar_scroll_blocos()

    # Login obrigatório
    abrir_login()
    carregar_blocos()
    window.mainloop()
