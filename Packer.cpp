// Packer.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include "Packer.h"

int main(int argc, char* argv[])
{
	//usage:packer <input.exe>  <output.exe>
	if (argc < 3) {
		printf("usage:packer <input.exe>  <output.exe>\n");
		return 0;
	}

	Packer packer(argv[1], argv[2]);
	packer.pack();
	return 0;
}