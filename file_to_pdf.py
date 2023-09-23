import sys
from jinja2 import Environment, FileSystemLoader, select_autoescape

template_env = Environment(
        loader=FileSystemLoader("templates"),
        autoescape=select_autoescape(['html', 'xml'])
    )
def generate_report(data):
    template = template_env.get_template("cve-report.html")
    rendered_html = template.render(data=data)
    return rendered_html
def save_to_html(filename, html_content):
    with open(filename, "w") as html_file:
        html_file.write(html_content)








# def create_pdf(input_filename, output_filename):
#     c = canvas.Canvas(output_filename, pagesize=letter)
#     width, height = letter

    
#     c.setFont("Helvetica", 14)

#     with open(input_filename, 'r') as file:
        
#         file_content = file.read()

#         c.drawString(50, height - 50, file_content)

#     c.save()

# if __name__ == "__main__":
#     if len(sys.argv) != 3:
#         print("Usage: python generate_pdf.py <input_file> <output_pdf>")
#         sys.exit(1)

#     input_file = sys.argv[1]
#     output_pdf = sys.argv[2]

#     if input_file.endswith(".txt"):
#         create_pdf(input_file, output_pdf)
#     else:
#         print("Input file must have a .txt extension.")
#         sys.exit(1)

#     print(f"PDF generated and saved as {output_pdf}")
