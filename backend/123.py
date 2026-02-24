import os

def save_paths_and_contents(root_folder, output_file):
    with open(output_file, "w", encoding="utf-8", errors="ignore") as out:

        for root, dirs, files in os.walk(root_folder):
            for file in files:
                file_path = os.path.join(root, file)

                # Записываем путь к файлу
                out.write(f"=== FILE: {file_path} ===\n")

                try:
                    # Пытаемся прочитать содержимое
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except Exception as e:
                    content = f"[ERROR reading file: {e}]"

                out.write(content + "\n\n")  # Добавлять отступы между файлами

if __name__ == "__main__":
    folder = r"C:\PyCharm 2024.3.4\more-stars-backend\app"  # <- Укажи путь к папке
    output = "paths.txt"  # <- файл куда всё сохранить
    save_paths_and_contents(folder, output)
    print("Готово! Все пути сохранены в", output)
