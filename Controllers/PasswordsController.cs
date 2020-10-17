using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Data.SqlClient;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Dapper;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using PasswordWallet.Models;

namespace PasswordWallet.Controllers
{
    public class PasswordsController : Controller
    {
        public string connectionString = "Data Source=LAPTOP-GHAEI4O2;Initial Catalog=sqlDb;Integrated Security=True";

        // GET: Passwords
        public ActionResult Index()
        {
            List<Passwords> passwords = new List<Passwords>();
            Users           user = new Users();

            IDbConnection db = new SqlConnection(connectionString);

            passwords = db.Query<Passwords>("Select * From Passwords").ToList();

            for (int i = passwords.Count() - 1; i >= 0; i--)
            {
                user = db.Query<Users>("Select * From Users WHERE Id =" + passwords[i].IdUser).SingleOrDefault();

                passwords[i].Password = DecryptPasswordAES(passwords[i].Password, user.PasswordHash);
            }

            return View(passwords);
        }

        // GET: Passwords/Details/5
        public ActionResult Details(int Id_User)
        {
            Passwords passwords = new Passwords();

            IDbConnection db = new SqlConnection(connectionString);

            passwords = db.Query<Passwords>("Select * From Passwords WHERE Id_User =" + Id_User, new { Id_User }).SingleOrDefault();

            return View(passwords);
        }

        // GET: Passwords/Create
        public ActionResult Create()
        {
            return View();
        }

        // POST: Customer/Create
        [HttpPost]
        public ActionResult Create(Passwords passwords)
        {
            try
            {
                int rowsAffected;
                string sqlQuery;
                Users user = new Users();
                IDbConnection db = new SqlConnection(connectionString);

                user = db.Query<Users>("Select * From Users WHERE Id =" + passwords.IdUser).SingleOrDefault();

                passwords.Password = EncryptPasswordAES(passwords.Password, user.PasswordHash);

                sqlQuery = "Insert Into Passwords (Id_User, Login, Description, WebAddress, Password) Values(@Id_User, @Login, @Description, @WebAddress, @Password)";

                rowsAffected = db.Execute(sqlQuery, passwords);

                return RedirectToAction("Index");
            }
            catch
            {
                return View();
            }
        }

        // GET: Passwords/Edit/5
        public ActionResult Edit(int id_User)
        {
            Passwords passwords = new Passwords();

            IDbConnection db = new SqlConnection(connectionString);

            passwords = db.Query<Passwords>("Select * From Passwords WHERE id_User =" + id_User, new { id_User }).SingleOrDefault();

            return View(passwords);
        }

        // POST: Passwords/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Edit(int id_User, Passwords passwords)
        {
            try
            {
                IDbConnection db = new SqlConnection(connectionString);

                string sqlQuery = "UPDATE Passwords set " +
                        "Login='" + passwords.Login +
                        "',Password='" + passwords.Password +
                        "',WebAddress='" + passwords.WebAddress +
                        "',Description='" + passwords.Description +
                        "' WHERE Id_User=" + passwords.IdUser;

                    int rowsAffected = db.Execute(sqlQuery);

                return RedirectToAction(nameof(Index));
            }
            catch
            {
                return View();
            }
        }

        // GET: Passwords/Delete/5
        public ActionResult Delete(int id_User)
        {
            Passwords passwords = new Passwords();

            IDbConnection db = new SqlConnection(connectionString);

            passwords = db.Query<Passwords>("Select * From Passwords WHERE Id_User =" + id_User, new { id_User }).SingleOrDefault();

            return View(passwords);
        }

        // POST: Passwords/Delete/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Delete(int id_User, IFormCollection collection)
        {
            try
            {
                IDbConnection db = new SqlConnection(connectionString);

                string sqlQuery = "Delete From Passwords WHERE Id_User = " + id_User;

                int rowsAffected = db.Execute(sqlQuery);

                return RedirectToAction(nameof(Index));
            }
            catch
            {
                return View();
            }
        }

        public string EncryptPasswordAES(string _password, string _primaryPasswordHash)
        {
            byte[] md5Key = this.CalculateMD5(_primaryPasswordHash);

            return this.EncryptAES(_password, md5Key);
        }

        public byte[] CalculateMD5(string _secretText)
        {
            string secretText = _secretText ?? "";
            var encoding = new System.Text.ASCIIEncoding();

            byte[] secretTextBytes = encoding.GetBytes(secretText);
            byte[] hashmessage;

            using (var md5 = MD5.Create())
            {
                hashmessage = md5.ComputeHash(secretTextBytes);
            }

            return hashmessage;
        }

        public string EncryptAES(string _password, byte[] _key)
        {
            // Check arguments.
            if (_password == null || _password.Length <= 0)
            {
                throw new ArgumentNullException("_password");
            }

            if (_key == null || _key.Length <= 0)
            {
                throw new ArgumentNullException("_key");
            }

            byte[] encrypted;
            byte[] iv = new byte[16];

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = _key;
                aesAlg.IV = iv;
                aesAlg.Padding = PaddingMode.Zeros;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(_password);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return Convert.ToBase64String(encrypted);
        }



        public string DecryptPasswordAES(string _passwordHash, string _primaryPasswordHash)
        {
            byte[] md5Key = this.CalculateMD5(_primaryPasswordHash);

            return this.DecryptAES(_passwordHash, md5Key);
        }

        public string DecryptAES(string _encryptedPassword, byte[] _key)
        {
            // Check arguments.
            if (_encryptedPassword == null || _encryptedPassword.Length <= 0)
            {
                throw new ArgumentNullException("_encryptedPassword");
            }

            if (_key == null || _key.Length <= 0)
            {
                throw new ArgumentNullException("_key");
            }

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;
            byte[] iv = new byte[16];
            byte[] encryptedBytes = Convert.FromBase64String(_encryptedPassword);

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = _key;
                aesAlg.IV = iv;
                aesAlg.Padding = PaddingMode.Zeros;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(encryptedBytes))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext.TrimEnd('\0');
        }
    }
}