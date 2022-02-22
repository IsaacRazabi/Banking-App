using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using API.Data;
using Microsoft.AspNetCore.Mvc;
using API.Entities;
using System.Security.Cryptography;
using System.Text;
using API.DTOs;
using Microsoft.EntityFrameworkCore;
using API.Interfaces;

namespace API.Controllers
{
    public class AccountController :BaseApiController
    {
         private readonly DataContext _context;
         private readonly ITokenService _tokenService;
         
        public AccountController (DataContext context, ITokenService tokenService)
        {
       _tokenService = tokenService;
       _context=context;
        }

        [HttpPost("register")]
        public async Task<ActionResult<UserDto>> Register (RegisterDto registerDto)
        {

if(await UserExist(registerDto.Username)) return BadRequest("Username is taken");


using var hmac = new HMACSHA512();
var user = new AppUser
{
    UserName = registerDto.Username.ToLower(),
        PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
        PasswordSalt = hmac.Key
};
//1. getting user data from frontside 2. crating a new object based on this data 3. arrange data to sql using .net
_context.Users.Add(user);
await _context.SaveChangesAsync();
return new UserDto
{
Username = user.UserName,
Token = _tokenService.CreateToken(user)
};
        }

        
        [HttpPost("login")]
        public async Task<ActionResult<UserDto>> login (LoginDto loginDto)
        {
var user = await _context.Users.SingleOrDefaultAsync(user=>user.UserName == loginDto.Username);
if (user == null) return Unauthorized("Invalid username");

using var hmac = new HMACSHA512(user.PasswordSalt);
var ComputeHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));

for (int i =0 ; i< ComputeHash.Length;i++)
{
if(ComputeHash[i] != user.PasswordHash[i]) return Unauthorized("Invalid password");  
};
return new UserDto
{
Username = user.UserName,
Token = _tokenService.CreateToken(user)
};
        }
        private async Task<bool> UserExist (string username)
        {
            return await _context.Users.AnyAsync(user => user.UserName == username.ToLower());
        }
    }
}