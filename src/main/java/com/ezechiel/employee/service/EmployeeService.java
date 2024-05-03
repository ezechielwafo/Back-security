package com.ezechiel.employee.service;

import com.ezechiel.employee.model.Employee;
import com.ezechiel.employee.repo.EmployeeRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Service
public class EmployeeService {
    private final EmployeeRepo employeeRepo;
    @Autowired
//    ici on injecte un objet de type eEmployerRepo dans le constructeur de EmployerService
    public EmployeeService(EmployeeRepo employeeRepo){
        this.employeeRepo = employeeRepo;
    }
    public Employee addEmployee(Employee employee){
    employee.setEmployeeCode(UUID.randomUUID().toString());
    return employeeRepo.save(employee);
    }
    public List<Employee> findAllEmployees(){
        return employeeRepo.findAll();
    }
    public Employee updateEmployee(Employee employee){
        Employee emp = findEmployeeById(employee.getId());
        if (emp != null) {
            emp.setEmployeeCode(employee.getEmployeeCode());
            emp.setEmail(employee.getEmail());
            emp.setName(employee.getName());
            emp.setPhone(employee.getPhone());
            emp.setImageUrl(employee.getImageUrl());
        }
        return employeeRepo.save(emp);
    }
    public Employee findEmployeeById(Long id){
        return employeeRepo.findEmployeeById(id).
                orElseThrow( () -> new UsernameNotFoundException("User by id " +id+ "was not found"));
    }
    public void deleteEmployee(Long id){
        System.out.println("\n\n\n id "+ id);
        employeeRepo.deleteById(id);
    }

}
