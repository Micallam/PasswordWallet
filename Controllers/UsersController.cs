using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Dapper;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using PasswordWallet.Models;

namespace PasswordWallet.Controllers
{
    public class UsersController : Controller
    {
        private static Random random = new Random();
        private const string  pepper = "Pepper";
        public string connectionString;

        private readonly IConfiguration _configuration;

        public UsersController(IConfiguration configuration)
        {
            _configuration = configuration;

            connectionString = _configuration.GetSection("ConnectionStrings").GetSection("DefaultConnection").Value;
        }

        // GET: Users
        public ActionResult Index()
        {
            return View();
        }

        // GET: Users/Details/5
        public ActionResult Details(int id)
        {
            return View();
        }

        // GET: Users/Create
        public ActionResult Create()
        {
            return View();
        }

        // POST: Users/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Create(Users users)
        {
            try
            {
                IDbConnection db = new SqlConnection(connectionString);

                users.Salt          = getSalt();
                users.PasswordHash = GetPasswordHashSHA512(users.PasswordHash, users.Salt, pepper);

                string sqlQuery = "Insert Into Users (Salt, Password_hash, Login, IsPassKeptAsHash) Values(@Salt, @Password_hash, @Login, @IsPassKeptAsHash)";

                int rowsAffected = db.Execute(sqlQuery, users);

                return View();
                //return RedirectToAction("Index");
            }
            catch
            {
                return View();
            }
    }

        // GET: Users/Edit/5
        public ActionResult Edit(int id)
        {
            return View();
        }

        // POST: Users/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Edit(int id, IFormCollection collection)
        {
            try
            {
                // TODO: Add update logic here

                return RedirectToAction(nameof(Index));
            }
            catch
            {
                return View();
            }
        }

        // GET: Users/Delete/5
        public ActionResult Delete(int id)
        {
            return View();
        }

        // POST: Users/Delete/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Delete(int id, IFormCollection collection)
        {
            try
            {
                // TODO: Add delete logic here

                return RedirectToAction(nameof(Index));
            }
            catch
            {
                return View();
            }
        }

        public string getSalt()
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            return new string(Enumerable.Repeat(chars, 10)
              .Select(s => s[random.Next(s.Length)]).ToArray());
        }

        public string GetPasswordHashSHA512(string _password, string _salt, string _pepper = pepper)
        {
            return CalculateSHA512(_password + _salt + _pepper);
        }

        public string CalculateSHA512(string _secretText)
        {
            string secretText = _secretText ?? "";
            var encoding = new ASCIIEncoding();

            byte[] secretTextBytes = encoding.GetBytes(secretText);

            using (var sha512 = SHA512.Create())
            {
                byte[] hashmessage = sha512.ComputeHash(secretTextBytes);

                return Convert.ToBase64String(hashmessage);
            }
        }
    }
}