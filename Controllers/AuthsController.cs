using JsonWebTokenApi.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace JsonWebTokenApi.Controllers
{
	[Route("api/auths")]
	[ApiController]
	public class AuthsController : ControllerBase
	{
		public static User user = new();
		private readonly IConfiguration _configuration;

		public AuthsController(IConfiguration configuration)
		{
			_configuration = configuration;
		}

		[HttpPost("register")]
		public IActionResult Register(UserDto request)
		{
			CreatePasswordHash(request.Password, out byte[] passwodHash, out byte[] passwordSalt);

			user.Username = request.Username;
			user.PasswordHash = passwodHash;
			user.PasswordSalt = passwordSalt;

			return Ok(user);
		}

		private static void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
		{
			using var hmac = new HMACSHA256();
			passwordSalt = hmac.Key;
			passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
		}

		[HttpPost("login")]
		public IActionResult Login(UserDto request)
		{
			if (user.Username != request.Username)
			{
				return BadRequest("Username Invalid!");
			}

			if (!VerifyPasswordHash(request.Password, user.PasswordHash!, user.PasswordSalt!))
			{
				return BadRequest("Wrong Password!");
			}

			string token = CreateToken(user);

			return Ok(token);
		}

		private static bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
		{
			using var hmac = new HMACSHA256(passwordSalt);
			var comuteHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
			return comuteHash.SequenceEqual(passwordHash);
		}

		private string CreateToken(User user)
		{
			List<Claim> claims = new()
			{
				new Claim(ClaimTypes.Name, user.Username!)
			};

			var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(
				_configuration.GetSection("AppSettings:Token").Value));

			var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature);

			var token = new JwtSecurityToken(
				claims: claims,
				signingCredentials: creds,
				expires: DateTime.Now.AddHours(1)
				);

			var jwt = new JwtSecurityTokenHandler().WriteToken(token);

			return jwt;
		}
	}
}
