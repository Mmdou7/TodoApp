using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using TodoApp.AppDBContext;
using TodoApp.Models;

namespace TodoApp.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    public class TodoController : ControllerBase
    {

        private readonly ApiDBContext _context;
        public TodoController(ApiDBContext context)
        {
            _context = context;
        }
        [HttpGet]
        public async Task<IActionResult> GetAllItemsAsync()
        {
            var items = await _context.Items.ToListAsync();
            return Ok(items);
        }
        [HttpPost]
        public async Task<IActionResult> AddItemAsync(ItemData model)
        {
            if(ModelState.IsValid)
            {
                 await _context.Items.AddAsync(model);
                 await _context.SaveChangesAsync();
                return CreatedAtAction("GetItemById", new {model.Id},model);  
            }
            return new JsonResult("Some thing went wrong"){ StatusCode = 500 };
        }
        [HttpGet("{id}")]
        public async Task<IActionResult> GetItemByIdAsync(int id)
        {
            var item = await _context.Items.FirstOrDefaultAsync(x=>x.Id == id);

            if (item == null)
                return NotFound();

            return Ok(item);
        }
        [HttpPut("{id}")]
        public async Task<IActionResult> UpdateItemAsync(ItemData model,int id)
        {
            if (model.Id != id)
                return BadRequest();

            var item = _context.Items.FirstOrDefault(x=>x.Id==model.Id);
            
            if (item == null)
                return NotFound();

            item.Title = model.Title;
            item.Description = model.Description;
            item.Done = model.Done;
            await _context.SaveChangesAsync();
            return NoContent();
        }
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteItemAsync(int id)
        {
            var Item = await _context.Items.FirstOrDefaultAsync(x => x.Id == id);

            if(Item == null) return NotFound();

            _context.Remove(Item);
            await _context.SaveChangesAsync();
            return Ok(Item);
        }
    }
}
