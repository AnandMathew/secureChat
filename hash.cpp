int main (int argc, char * arg[])
{
    // generate challenge

    int byte_count = 16;
    char P[128];
    FILE *fp;
    fp = fopen("/dev/urandom", "r");
    fread(&R, 1, byte_count, fp);
    fclose(fp);

    std::cout << "P: "<< P << "\n";

    sha256('A98uh9nj9-098')

    return 0;
}