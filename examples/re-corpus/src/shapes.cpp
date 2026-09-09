#include <string>
#include <vector>
#include <iostream>
struct Shape { virtual double area() const = 0; virtual ~Shape(){} };
struct Circle : Shape { double r; Circle(double r):r(r){} double area() const override { return 3.14159*r*r; } };
struct Rect : Shape { double w,h; Rect(double w,double h):w(w),h(h){} double area() const override { return w*h; } };
int main(int argc, char**argv){
    std::vector<Shape*> v; v.push_back(new Circle(argc)); v.push_back(new Rect(argc,2));
    double t=0; for(auto*s:v){ try{ t+=s->area(); }catch(...){ } }
    std::string name = argc>1?argv[1]:"anon";
    std::cout << name << " total=" << t << "\n"; return (int)t;
}
