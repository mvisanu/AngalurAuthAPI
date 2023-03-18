AngularAuthAPI
How to add database entityframework core
-------------------------------------------------
Insall 4 packages
- Microsoft.EntityFrameworkCore
- Microsoft.EntityFrameworkCore.Design
- Microsoft.EntityFrameworkCore.SqlServer
- Microsoft.EntityFrameworkCore.Tools

program.cs
builder.Services.AddDbContext<AppDbContext>(options =>
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("SqlServerConnStr"));
});

AppSettings.Jason
"ConnectionStrings": {
    "SqlServerConnStr": "Data Source=localhost;Initial Catalog=AuthAPIDb; Integrated Security = true;"
  }

AppDbContext.cs
public class AppDbContext: DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {            
        }
        public DbSet<User> Users { get; set; }
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            //base.OnModelCreating(modelBuilder);
            modelBuilder.Entity<User>().ToTable("users");
        }
    }

package manager console
add-migration v1
update-database