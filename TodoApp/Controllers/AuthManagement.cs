using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using TodoApp.Configuration;
using TodoApp.Models.DTOs.Requests;
using TodoApp.Models.DTOs.Responses;

namespace TodoApp.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthManagement : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly JwtConfig _jwtConfig;
        public AuthManagement(IOptionsMonitor<JwtConfig> optionsMonitor,
            UserManager<IdentityUser> userManager)
        {
            _userManager = userManager;
            _jwtConfig = optionsMonitor.CurrentValue;
        }

        [HttpPost]
        [Route("Register")]
        public async Task<IActionResult> Register([FromBody] UserRegistrationDto user)
        {
            if (ModelState.IsValid)
            {
                var existingUser = _userManager.FindByEmailAsync(user.Email);
                if (existingUser != null)
                {
                    return BadRequest(new RegistrationResponseDto()
                    {
                        Errors = new List<string>()
                            {
                                "Email registered before"
                            },
                        Success = false
                    });
                }
                var newUser = new IdentityUser() { UserName = user.UserName, Email = user.Email };
                var isCreated = await _userManager.CreateAsync(newUser,user.Password);
                if (isCreated.Succeeded)
                {
                    var jwtToken = GenerateJwtToken(newUser);

                    return Ok(new RegistrationResponseDto()
                    {
                        Success = true,
                        Token = jwtToken
                    });
                }
                else
                {
                    return BadRequest(new RegistrationResponseDto()
                    {
                        Errors = isCreated.Errors.Select(x=>x.Description).ToList(),
                        Success = false
                    });
                }
            }
            return BadRequest( new RegistrationResponseDto()
            {
                Errors = new List<string>()
                {
                    "Invalid Payload"
                },
                Success = false
            });
        }
        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login([FromBody] UserLoginDto user)
        {
            if (ModelState.IsValid)
            {
                var existingUser = await _userManager.FindByEmailAsync(user.Email);

                if (existingUser == null)
                {
                    return BadRequest(new RegistrationResponseDto()
                    {
                        Errors = new List<string>()
                            {
                                "Invalid Data"
                            },
                        Success = false
                    });
                }

                var isCorrect = await _userManager.CheckPasswordAsync(existingUser, user.Password);
                if (!isCorrect)
                {
                    return BadRequest(new RegistrationResponseDto()
                    {
                        Errors = new List<string>()
                            {
                                "Invalid Data"
                            },
                        Success = false
                    });
                }

                var jwtToken = GenerateJwtToken(existingUser);

                return Ok(new RegistrationResponseDto()
                {
                    Success = true,
                    Token = jwtToken
                });
            }

            return BadRequest(new RegistrationResponseDto()
            {
                Errors = new List<string>()
                {
                    "Invalid Payload"
                },
                Success = false
            });
            
        }
        private string GenerateJwtToken(IdentityUser user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();

            var Key = Encoding.ASCII.GetBytes(_jwtConfig.Secret);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim("Id", user.Id),
                    new Claim(JwtRegisteredClaimNames.Email, user.Email),
                    new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                }),
                Expires = DateTime.UtcNow.AddHours(6),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(Key),SecurityAlgorithms.HmacSha256)
            };

            var token = jwtTokenHandler.CreateToken(tokenDescriptor);

            var jwtToken = jwtTokenHandler.WriteToken(token);

            return jwtToken;
        }
    }
}
