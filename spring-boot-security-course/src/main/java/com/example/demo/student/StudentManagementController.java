package com.example.demo.student;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/student")
public class StudentManagementController {
    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1, "James Bond"),
            new Student(2, "Maria Jones"),
            new Student(3, "Anna Smith")
    );

    @GetMapping()
    @PreAuthorize("hasAnyRole('ROLE_ADMIN,  ROLE_ADMIN_TRAINEE')")
    public List<Student> getStudents() {
        return STUDENTS;
    }

    @PostMapping()
    @PreAuthorize("hasAnyAuthority('student:write, course:write')")
    public void registerNewStudent(@RequestBody Student student) {
        System.out.println(student + " was registered");
    }

    @DeleteMapping(path = "{studentId}")
    public void deleteStudent(@PathVariable("studentId") Integer id) {
        System.out.println("student with id " + id + " was deleted");
    }

    @PutMapping(path = "{studentId}")
    public void updateStudent(@RequestBody Student student, @PathVariable("studentId") Integer id) {
        System.out.printf("%s %S%n", id, student);
    }
}
