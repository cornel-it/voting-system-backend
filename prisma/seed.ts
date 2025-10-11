import { PrismaClient, UserRole } from '@prisma/client';
import * as bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

async function main() {
  console.log('🌱 Starting database seeding...');

  // Create Super Admin User
  const hashedPassword = await bcrypt.hash('admin123', 12);

  const superAdmin = await prisma.user.upsert({
    where: { email: 'admin@unielect.com' },
    update: {},
    create: {
      studentId: 'ADM001-0001/2024',
      email: 'admin@unielect.com',
      firstName: 'System',
      lastName: 'Administrator',
      password: hashedPassword,
      faculty: 'Administration',
      department: 'IT Department',
      course: 'System Administration',
      yearOfStudy: 1,
      admissionYear: 2024,
      role: UserRole.SUPER_ADMIN,
      isActive: true,
      isVerified: true,
      emailVerified: new Date(),
      bio: 'System Administrator for UniElect Platform',
    },
  });

  console.log('✅ Created Super Admin:', superAdmin.email);

  // Create Admin User
  const admin = await prisma.user.upsert({
    where: { email: 'moderator@unielect.com' },
    update: {},
    create: {
      studentId: 'ADM002-0001/2024',
      email: 'moderator@unielect.com',
      firstName: 'Election',
      lastName: 'Moderator',
      password: hashedPassword,
      faculty: 'Administration',
      department: 'Student Affairs',
      course: 'Public Administration',
      yearOfStudy: 2,
      admissionYear: 2023,
      role: UserRole.ADMIN,
      isActive: true,
      isVerified: true,
      emailVerified: new Date(),
      bio: 'Election Administrator and Moderator',
    },
  });

  console.log('✅ Created Admin:', admin.email);

  // Create Sample Voters
  const voters = [];
  for (let i = 1; i <= 5; i++) {
    const voter = await prisma.user.upsert({
      where: { email: `student${i}@unielect.com` },
      update: {},
      create: {
        studentId: `STU00${i}-000${i}/2024`,
        email: `student${i}@unielect.com`,
        firstName: `Student${i}`,
        lastName: 'User',
        password: hashedPassword,
        faculty: i <= 2 ? 'Engineering' : i <= 4 ? 'Business' : 'Arts',
        department: i <= 2 ? 'Computer Science' : i <= 4 ? 'Business Administration' : 'Literature',
        course: i <= 2 ? 'Computer Science' : i <= 4 ? 'MBA' : 'English Literature',
        yearOfStudy: Math.floor(Math.random() * 4) + 1,
        admissionYear: 2024 - Math.floor(Math.random() * 4),
        role: UserRole.VOTER,
        isActive: true,
        isVerified: true,
        emailVerified: new Date(),
        bio: `Student voter ${i} for testing purposes`,
      },
    });
    voters.push(voter);
  }

  console.log(`✅ Created ${voters.length} sample voters`);

  // Create System Configuration
  const systemConfigs = [
    {
      key: 'system.name',
      value: 'UniElect',
      description: 'System name',
      category: 'branding',
      isPublic: true,
    },
    {
      key: 'system.version',
      value: '1.0.0',
      description: 'System version',
      category: 'system',
      isPublic: true,
    },
    {
      key: 'voting.min_election_duration_hours',
      value: 2,
      description: 'Minimum election duration in hours',
      category: 'voting',
      isPublic: false,
    },
    {
      key: 'security.max_login_attempts',
      value: 5,
      description: 'Maximum login attempts before lockout',
      category: 'security',
      isPublic: false,
    },
  ];

  for (const config of systemConfigs) {
    await prisma.systemConfig.upsert({
      where: { key: config.key },
      update: { value: config.value },
      create: config,
    });
  }

  console.log('✅ Created system configurations');

  console.log('🎉 Database seeding completed successfully!');
  console.log('\n📋 Created Resources:');
  console.log(`   👤 Users: ${voters.length + 2} (1 Super Admin, 1 Admin, ${voters.length} Voters)`);
  console.log(`   ⚙️  System Configs: ${systemConfigs.length}`);
  console.log('\n🔐 Default Login Credentials:');
  console.log('   Super Admin: admin@unielect.com / admin123');
  console.log('   Admin: moderator@unielect.com / admin123');
  console.log('   Students: student1@unielect.com to student5@unielect.com / admin123');
}

main()
  .catch((e) => {
    console.error('❌ Error during seeding:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });